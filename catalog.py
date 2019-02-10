from flask import Flask, render_template, request
from flask import redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Catalog, Base, CatalogItem, User
from flask import session as login_session
import random
import string
import json
from sqlalchemy.pool import StaticPool
from flask import make_response
import requests
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2

app = Flask(__name__)

# Client Secrets establishment
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"

# Connect to Database and create database session
engine = create_engine(
    'sqlite:///catalogItem.db', connect_args={
        'check_same_thread': False}, poolclass=StaticPool)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: '\
        '150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type'\
        '=fb_exchange_token&client_id=%s&client_secret='\
        '%s&fb_exchange_token=%s' % (
            app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?'\
        'access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture'\
        '?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: '\
        '150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


# User functions for adding and checking users
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()

    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        print ("This failed for some reason")
        return None


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
        % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' \
        % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Show all categories
@app.route('/')
@app.route('/catalog/')
def showCatalog():
    query = ('select catalog_item.name as catalogName, '
             'catalog.name as categoryName, catalog.id '
             'as catalogID, catalog_item.id '
             'as itemID from catalog_item inner join '
             'catalog on (catalog_item.category_id'
             '= catalog.id) order by catalog_item.id desc limit (10)')

    catalogItems = session.execute(query)
    catalogs = session.query(Catalog)
    return render_template(
        'catalogs.html', catalogs=catalogs, catalogItems=catalogItems)


# Json for all Categories
@app.route('/catalog/JSON')
def catalogJSON():
    restaurants = session.query(Catalog).all()
    return jsonify(restaurants=[r.serialize for r in restaurants])


# Create a new category
@app.route('/category/new/', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newCategory = Catalog(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newCategory)
        flash('New Category %s Successfully Created' % newCategory.name)
        session.commit()
        return redirect(url_for('showCatalog'))
    else:
        return render_template('newCategory.html')


# Edit a Category

@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
def editCategory(category_id):
    editedCategory = session.query(Catalog).filter_by(id=category_id).one()
    editedOwner = session.query(User).filter_by(id=editedCategory.user_id)
    if editedCategory.user_id != login_session['user_id']:
        return render_template('unauthorized.html', categoryOwner=editedOwner)
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
            session.add(editedCategory)
            session.commit()
            flash('Category %s Successfully Updated' % (editedCategory.name))
            return redirect(url_for('showCatalog'))
    else:
        return render_template('editCategory.html', catalog=editedCategory)


# Delete a Category
@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_id):
    categoryToDelete = session.query(Catalog).filter_by(id=category_id).one()
    editedOwner = session.query(User).filter_by(id=categoryToDelete.user_id)
    if categoryToDelete.user_id != login_session['user_id']:
        return render_template('unauthorized.html', categoryOwner=editedOwner)
    if request.method == 'POST':
        session.delete(categoryToDelete)
        session.commit()
        flash('%s Successfully Deleted' % categoryToDelete.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template('deleteCategory.html', catalog=categoryToDelete)


# Show Items for a Category
@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/items/')
def showItems(category_id):
    catalog = session.query(Catalog).filter_by(id=category_id).one()
    items = session.query(CatalogItem).filter_by(
        category_id=category_id).all()
    print ('Created by: ' + str(catalog.user_id))
    return render_template('catalogItems.html', items=items, catalog=catalog)


# JSON for Items in a category
@app.route('/category/<int:category_id>/items/JSON')
def categoryListJSON(category_id):
    category = session.query(Catalog).filter_by(id=category_id).one()
    items = session.query(CatalogItem).filter_by(
        category_id=category_id).all()
    return jsonify(CatalogItem=[i.serialize for i in items])


# Create a new catalog item
@app.route('/category/catalog/new/', methods=['GET', 'POST'])
def newCatalogItem():
    categoryList = session.query(Catalog)
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newItem = CatalogItem(
            name=request.form['name'], description=request.form[
                           'description'], user_id=login_session[
                               'user_id'], category_id=request.form[
                                   'category'])
        session.add(newItem)
        session.commit()
        flash('New category %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showCatalog'))
    else:
        return render_template(
            'newCatalogItem.html', categoryList=categoryList)


# show a catalog item
@app.route('/category/<int:category_id>/catalog/<int:catalog_id>/show')
def showCatalogItem(category_id, catalog_id):
    shownItem = session.query(CatalogItem).filter_by(id=catalog_id).one()
    return render_template(
            'showCatalogItem.html', category_id=category_id,
            catalog_id=catalog_id, item=shownItem)


# JSON of single catalog item
@app.route('/category/<int:category_id>/catalog/<int:catalog_id>/JSON')
def catalogItemJSON(category_id, catalog_id):
    Catalog_Item = session.query(CatalogItem).filter_by(id=catalog_id).one()
    return jsonify(Catalog_Item=Catalog_Item.serialize)


# Edit a catalog item
@app.route('/category/<int:category_id>/catalog/<int:catalog_id>/edit',
           methods=['GET', 'POST'])
def editCatalogItem(category_id, catalog_id):
    categoryList = session.query(Catalog)
    editedItem = session.query(CatalogItem).filter_by(id=catalog_id).one()
    editedOwner = session.query(User).filter_by(id=editedItem.user_id)
    if 'username' not in login_session:
        return redirect('/login')
    if editedItem.user_id != login_session['user_id']:
        return render_template('unauthorized.html', categoryOwner=editedOwner)
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['category']:
            editedItem.category_id = request.form['category']
        session.add(editedItem)
        session.commit()
        flash('Successfully Edited Catalog Item: %s' % editedItem.name)
        return redirect(url_for('showCatalog'))
    else:

        return render_template(
            'editCatalogItem.html', category_id=category_id,
            catalog_id=catalog_id, item=editedItem, categoryList=categoryList)


# Delete a catalog item
@app.route('/category/<int:category_id>/catalog/<int:catalog_id>/delete',
           methods=['GET', 'POST'])
def deleteCatalogItem(category_id, catalog_id):
    itemToDelete = session.query(CatalogItem).filter_by(id=catalog_id).one()
    userTable = session.query(User).filter_by(id=itemToDelete.user_id).one()
    editedOwner = session.query(User).filter_by(id=itemToDelete.user_id)
    if 'username' not in login_session:
        return redirect('/login')
    if itemToDelete.user_id != login_session['user_id']:
        return render_template('unauthorized.html', categoryOwner=editedOwner)
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Successfully Deleted Catalog Item: %s' % itemToDelete.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template('deleteCatalogItem.html', item=itemToDelete)


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))


if __name__ == '__main__':
    app.secret_key = 'kyles_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
