# Kyle's Item Catalog  Project

This is a project designed from scratch. 
1. Will be using Python Framework
2. Implementing third-party OAuth authentication
3. Using various HTTP methods related to CRUD operations

## Install
1. Set up Vagrant and SSH into the machine
2. navigate to the Vagrant > Catalog folder.
3. set up the following files:

  - Create database
  - Run `python database_setup.py`
  
  - Load data into the database
  - Run `python loadCatalogItems.py`

4. Once database is configured and data has been added run the following command to start the application
  - `python catalog.py`
5. Navigate to localhost:5000 on your machine to view the application
6. In order to create, edit, update, delete, please log into the system with google or facebook.