from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Catalog, Base, CatalogItem, User

engine = create_engine('sqlite:///catalogItem.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()


# Create dummy user
User1 = User(name="Kyle Burger", email="kwb5105@gmail.com",
             picture='https://shortlist.imgix.net/app/uploads/2015/12/04110243/50-of-the-best-star-wars-quotes-60-852x568.jpg?w=1640&h=1&fit=max&auto=format%2Ccompress')
session.add(User1)
session.commit()

# Catalog Items for Football
catalog1 = Catalog(user_id=1, name="Football")

session.add(catalog1)
session.commit()


categoryItem1 = CatalogItem(user_id=1, name="Socks", description="Socks are critical for showing how cool you are on the court.", catalog=catalog1)

session.add(categoryItem1)
session.commit()

categoryItem2 = CatalogItem(user_id=1, name="Jersey", description="The Jersey show's everyone which team you are a part of during the game.", catalog=catalog1)

session.add(categoryItem2)
session.commit()


# Catalog Items for Soccer
catalog2 = Catalog(user_id=1, name="Soccer")

session.add(catalog2)
session.commit()



categoryItem1 = CatalogItem(user_id=1, name="Socks", description="Socks are critical for showing how cool you are on the court.", catalog=catalog2)

session.add(categoryItem1)
session.commit()


categoryItem2 = CatalogItem(user_id=1, name="Jersey", description="The Jersey show's everyone which team you are a part of during the game.", catalog=catalog2)

session.add(categoryItem2)
session.commit()


# Catalog items for Basketball
catalog3 = Catalog(user_id=1, name="Basketball")

session.add(catalog3)
session.commit()


categoryItem1 = CatalogItem(user_id=1, name="Socks", description="Socks are critical for showing how cool you are on the court.", catalog=catalog3)

session.add(categoryItem1)
session.commit()

categoryItem2 = CatalogItem(user_id=1, name="Jersey", description="The Jersey show's everyone which team you are a part of during the game.", catalog=catalog3)

session.add(categoryItem2)
session.commit()



print "added category items!"