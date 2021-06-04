# nba_expansion_league

### What is it
- [x] Deployed a RESTless API to the Google Cloud Platform (GCP) allowing users to create nba expansion leagues and giving them full control of creation and placement of players, teams, and owners. 
- [x] Utilized Google Oauth 2.0 for authentication/authorization and user/owner entity creation in GCP's Datastore.
- [x] Tested the CRUD operations for all entities using Postman collections and environment. 
- [x] Refined data-model to include entity links for easy viewing and documented all API endpoints for users. 
- [x] Provided Docker file for containerization of application and a guide to on how to achieve this.  
### How to use 
- [x] Refer to the data-model and api documentation pdf in this repo. 
### GCP as PAAS (how it is right now)
- [x] We can use our deployed Google App Engine application and use GCP as a Paas.
- [x] We do not get access to low level programming interfaces. 
- [x] We do not get much access to the hard drive hosting the applications. 
- [x] We do not worry about keeping hardware and OS up to date. 

### GCP as a IAAS.
- [x] We can use our docker file to deploy our application to a VM instance using Google Compute Engine
- [x] We don't have a domain name if we do this. 
- [x] We do have more control over what hardware we use, what packages we use, etc. 

### How to set up using Docker + GCP (as IAAS)
- [x] Go to terminal and run gcloud builds submit gcr.io/project_name/docker_file_name .
- [x] Go to consolecloud.google.com and then click on menu
- [x] Go to container registry and copy the link for your docker file
- [x] Go to google compute enginer  then VM instances and click create instance
- [x] Because we don't want to spend alot of money we choose the smallest memory storage
- [x] Click on "deploy container image to this VM instance" and paste the link 
- [x] Click on "Allow HTTP traffic" and "Allow HTTPS traffic"
- [x] You will get the IP for the VM and now you can use this address to do any API calls
