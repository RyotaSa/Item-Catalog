# Item-Catalog

**Description**
The project shows to build web application that queries a database with API endpoints and web pages.

Item catalog project contains items category including with items and developping a RESTful web application using the Python framework Flask.
By implementing OAuth authentication(Google signin and Facebook signin), you could manipulate with CRUD operations by using an Object-Relational Mapping (ORM) layer(SQLAlchemy-Database) and realize how it works.

## Getting Started
**Prerequisite**
- Install Vagrant, VirtualBox
- Use Python 3
- Use Git Bash terminal(windows users) or terminal

**Instruction**
1. Launch the Virtual Machine with the command in a repository:
` vagrant up `
2. SSH with the command:
` vagrant ssh `
3. Go to vagrant directory:
` cd /vagrant `
4. Populate the database with some data by running in the VM:
` python data.py `
5. Run this command:
` python project.py `
6. Check the webapplication to:
` http://localhost:5000 `

* To shutdown the VM with command: `vagrant halt`

## API Endpoints
* All Catalog names in JSON: `/catalog/JSON`
* Item catalog in JSON: `/catalog/<int:category_id>/items/JSON`
* JSON API to view catalog Information: `/catalog/<int:category_id>/items/<int:menu_id>/JSON`

