from google.cloud import datastore
from flask import Flask, request, redirect, url_for, render_template, session, make_response
import json
import random
import secrets
import requests
import constants
from datetime import datetime
from helper_functions import response, check_missing_attr, check_missing_attr_player
from google.oauth2 import id_token
from google.auth.transport import requests as g_requests

secret = "secret_key"
app = Flask(__name__)
app.secret_key = secret
#app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=True)
client = datastore.Client()

#TODO: CHANGE CLIENT ID AND SECRET AND REDIRECT URI 
CLIENT_ID = "1043169130124-52pe66gvrbicsndbegtas9n04dkduf93.apps.googleusercontent.com"
CLIENT_SECRET = "D4--sOQxez-aQ3H_iEfeZhAU"
SCOPE = "https://www.googleapis.com/auth/userinfo.profile"
REDIRECT_URI = 'https://nba-expansion-league.wl.r.appspot.com/oauth' # this is where we want google to redirect us to
# local testing 
#REDIRECT_URI = 'http://localhost:8080/oauth'

def verify_jwt(request):
    #print(request.headers)
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
        try:
            # Specify the CLIENT_ID of the app that accesses the backend:
            idinfo = id_token.verify_oauth2_token(token, g_requests.Request(), CLIENT_ID)

            # ID token is valid. Get the user's Google Account ID from the decoded token.
            userid = idinfo['sub']
            return userid
        except ValueError:
            # Invalid token
            userid = "INVALID"
            return userid
    else:
        #print('auth not in headers')
        return "INVALID"

def get_jwt_user_creation(jwt_token):
    try:
        # Specify the CLIENT_ID of the app that accesses the backend:
        idinfo = id_token.verify_oauth2_token(jwt_token, g_requests.Request(), CLIENT_ID)

        # ID token is valid. Get the user's Google Account ID from the decoded token.
        userid = idinfo['sub']
        return userid
    except ValueError:
        # Invalid token
        userid = "INVALID"
        return userid
@app.route('/')
def index():
    return render_template("welcome.html")

@app.route('/infoPage')
def infoPage():
    if 'credentials' not in session:
        return redirect(url_for('oauth'))
    #print(session)
    try:
        credentials = session['credentials']
        headers = {'Authorization': 'Bearer {}'.format(credentials)}
        req_uri = ' https://people.googleapis.com/v1/people/me?personFields=names'
        res = requests.get(req_uri, headers=headers) # response 
        # parse res + separate into first/last name vars
        #print(res.json())
        first_name = res.json().get('names')[0].get('givenName')
        last_name = res.json().get('names')[0].get('familyName')
        jwt_user = session.get("jwt_token")
        unique_id = get_jwt_user_creation(jwt_user)
        current_time = datetime.today().strftime('%m/%d/%Y')
        r_data = {
            'name': first_name, 
            'net_worth': 1000000000,
            'created_date': current_time
        }
        new_headers ={'Authorization': 'Bearer {}'.format(jwt_user)}
        new_request = requests.post('http://localhost:8080/owners', headers=new_headers, json=r_data)
        #print(new_request)
        # new_request = requests.post('https://nba-expansion-league.wl.r.appspot.com/owners', headers={'Content-Type':'application/json',
        #        'Authorization': 'Bearer {}'.format(jwt_user)}, data=r_data)
        session.pop('jwt_token')
        session.pop('credentials')
        return render_template('user_info.html', first_name=first_name, last_name=last_name,jwt_user = jwt_user, unique_id = unique_id)
    except TypeError:
        session.pop('jwt_token')
        session.pop('credentials')
        return redirect(url_for('oauth'))

@app.route('/oauth')
def oauth():
    if 'code' not in request.args:
        state = "superSave" + str(random.randint(0,1000000000000))
        session['state'] = state
        auth_uri = ('https://accounts.google.com/o/oauth2/v2/auth?response_type=code'
                '&client_id={}&redirect_uri={}&scope={}&state={}').format(CLIENT_ID, REDIRECT_URI, SCOPE, state)
        return redirect(auth_uri)
    else:
        auth_code = request.args.get('code') # have code here
        data = {'code': auth_code,
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET,
                'redirect_uri': REDIRECT_URI,
                'grant_type': 'authorization_code'}
        r = requests.post('https://www.googleapis.com/oauth2/v4/token', data=data) # send post to get access token
        session['credentials'] = r.json().get('access_token') # here we have the token 
        session['jwt_token'] = r.json().get('id_token') # owner_id is the json web token
        return redirect(url_for('infoPage')) 

# teams routing 

@app.route('/teams', methods=['POST', 'GET']) # create and view all teams
def teams_post():
    jwt = verify_jwt(request)
    if request.method == 'POST':
        if jwt != "INVALID":
            #print('here')
            content_type = request.mimetype
            # checking if request is JSON
            if content_type == "application/json":
                # check the request for 3 attributes
                content = request.get_json()
                # we do not need to do input validation
                obj_name, obj_city, obj_salary_cap = check_missing_attr(content, False, False, False)
                #print(obj_name, obj_city, obj_salary_cap)
                # check if content name is a duplicate
                if obj_name and obj_city and obj_salary_cap:
                    # set up query for data store
                    query = client.query(kind=constants.teams)
                    # get results from query
                    results = list(query.fetch())
                    # create entity
                    new_team = datastore.entity.Entity(key=client.key(constants.teams))
                    # store the attributes into new entity
                    new_team.update({"name": content["name"], "city": content["city"],
                    "salary_capacity": content["salary_capacity"], "players":[], "owner": jwt})
                    # put the new team info into our data store
                    client.put(new_team)
                    # get owner list so that we can get the owner id 
                    owner_q = client.query(kind=constants.owners)
                    owner_q.add_filter("unique_id", "=", jwt)
                    owner_list = list(owner_q.fetch())
                    # add id to get
                    for owner in owner_list:
                        owner["id"] = owner.key.id
                    # get owner id
                    owner_id = owner_list[0]['id']
                    # get owner by id
                    owner_key = client.key(constants.owners, int(owner_id))
                    owner = client.get(key=owner_key)
                    # set team id
                    new_team["id"] = new_team.key.id
                    # put url in this new team -- doesnt change in datastore bc after .put()
                    new_team["self"] = request.base_url + "/" + str(new_team.id)
                    # set to owners list of teams
                    arr = owner["teams"]
                    # the team is added to their list
                    arr.append(new_team.key.id)
                    owner.update({"name": owner["name"], "net_worth": owner["net_worth"], "created_date": owner["created_date"], "teams":arr, "unique_id": owner["unique_id"]})
                    client.put(owner)
                    res = make_response(json.dumps(new_team))
                    res.headers.set('Content-Type', 'application/json')
                    res.status_code = 201
                    return res
                err = {"Error": "The request object is missing at least one of the required attributes."}
                res = response(err, 400)
                return res
            else:
                res = response({"Error": "Unsupported Media Type"}, 415)
                return res
        else:
            res = response({"Error": "Unauthorized"}, 401)
            return res

    # view all teams for valid jwt 
    elif request.method == 'GET':
        # set up query for data store
        if jwt != "INVALID":
            query = client.query(kind=constants.teams)
            query.add_filter("owner", "=", jwt) # might need type casting to be a string instead of an int, bc jwt might be string instead of int. check bc this might cause issues in other tests
            # start of pagination
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            l_iterator = query.fetch(limit= q_limit, offset=q_offset)
            pages = l_iterator.pages
            results = list(next(pages))
            # if we have this next_page_token then we update for next query
            if l_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None
            for team in results:
                team["id"] = team.key.id
                team["self"] =  request.base_url + "/" + str(team.key.id)
                if 'players' in team.keys():
                    # add self to players
                    for player in team["players"]:
                        root = request.url_root[:-1]
                        player["self"] = root + url_for('players.players_find_edit_delete', id = player["id"])

            output = {"teams": results}
            if next_url:
                output["next"] = next_url
            return (json.dumps(output),200)
        else:
            res = response({"Error": "Unauthorized"}, 401)
            return res
    else:
        res = response({"Error": "Method Not Allowed"}, 405)
        return res 

# read, update, delete of CRUD
@app.route('/teams/<team_id>', methods=['PATCH', 'PUT', 'DELETE', 'GET'])
def teams_find_edit_delete(team_id): 
    jwt = verify_jwt(request)
    # DONE - GET w/ id and jwt
    if request.method == 'GET':
        if jwt!= "INVALID":
            accept_headers = request.accept_mimetypes
            # set the id to be the key for client query     
            team_key = client.key(constants.teams, int(team_id))
            team = client.get(key=team_key)
            if not team:
                error_404 = {"Error": "No team with this team_id exists"}
                res = response(error_404, 404)
                return res
            # line below might be wrong - check the return of team (might have to make it a list & iterate like in example)
            team["id"] = team.key.id
            # put url in this new obj
            team["self"] = request.base_url
            if 'players' in team.keys():
                # add self to players
                for player in team["players"]:
                    root = request.url_root[:-1]
                    player["self"] = root + url_for('players.players_find_edit_delete', id = player["id"])
            # client wants response in json format
            if "application/json" in request.accept_mimetypes:
                if team["owner"] == jwt:
                    res = make_response(json.dumps(team))
                    res.headers.set('Content-Type', 'application/json')
                    res.status_code = 200
                    return res
                else:
                    # non owner cannot access team
                    res = response({"Error": "Forbidden"},403)
                    return res
            # client wants response in format that server does not support
            else:
                res = response({"Error": "Not Acceptable"}, 406)
                return res
        else:
            res = response({"Error": "Unauthorized"}, 401)
            return res
    # PATCH -- DONE 
    elif request.method == "PATCH":
        content_type = request.mimetype
        # checking if request is JSON
        if content_type == "application/json":
            if jwt!= "INVALID":
                # check the request for 3 attributes
                content = request.get_json()
                # this the team we need to update
                team_key = client.key(constants.teams, int(team_id))
                team = client.get(key=team_key)
                curr_team = team
                if not team:
                    error_404 = {"Error": "No team with this team_id exists"}
                    res = response(error_404, 404)
                    return res
                curr_team["id"] = curr_team.key.id
                # check which of 3 attributes are in request:
                missing_name, missing_city, missing_salary_capacity = check_missing_attr(content, False, False, False)
                print(missing_name, missing_city, missing_salary_capacity)
                if missing_name and missing_city and missing_salary_capacity:
                    # update object
                    team.update({"name": content["name"], "city": content["city"], "salary_capacity": content["salary_capacity"], "players": curr_team["players"], "owner": curr_team["owner"]})
                elif missing_name and missing_city:
                    # update object
                    team.update({"name": content["name"], "city": content["city"], "salary_capacity": curr_team["salary_capacity"], "players": curr_team["players"], "owner": curr_team["owner"]})                
                elif missing_city and missing_salary_capacity:
                    # update object
                    team.update({"name": curr_team["name"], "city": content["city"], "salary_capacity": content["salary_capacity"], "players": curr_team["players"], "owner": curr_team["owner"]})  
                elif missing_name and missing_salary_capacity:
                    # update object
                    team.update({"name": content["name"], "city": curr_team["city"], "salary_capacity": content["salary_capacity"], "players": curr_team["players"], "owner": curr_team["owner"]})
                elif missing_name:
                    # update object
                    team.update({"name": content["name"], "city": curr_team["city"], "salary_capacity": curr_team["salary_capacity"], "players": curr_team["players"], "owner": curr_team["owner"]})  
                elif missing_city:
                    # update object
                    team.update({"name": curr_team["name"], "city": content["city"], "salary_capacity": curr_team["salary_capacity"], "players": curr_team["players"], "owner": curr_team["owner"]})  
                elif missing_salary_capacity:
                    team.update({"name": curr_team["name"], "city": curr_team["city"], "salary_capacity": content["salary_capacity"], "players": curr_team["players"], "owner": curr_team["owner"]})
                # add id and url to the team and return it -- wont change the team in data store bc we have used a put
                client.put(team)
                team["id"] = team.key.id
                team["self"] = request.base_url
                if team["owner"] == jwt:
                    res = make_response(json.dumps(team))
                    res.headers.set('Content-Type', 'application/json')
                    res.status_code = 200
                    return res
                else:
                    # non owner cannot access team
                    res = response({"Error": "Forbidden"},403)
                    return res
            else:
                res = response({"Error": "Unauthorized"}, 401)
                return res
        else:
            res = response({"Error": "Unsupported Media Type"}, 415)
            return res 
    # PUT -- DONE
    elif request.method == "PUT":
        content_type = request.mimetype
        # checking if request is JSON
        if content_type == "application/json":
            if jwt!= "INVALID":
                # no input validation -- expected to have all attributes and all of them being correct
                # check the request for 3 attributes
                content = request.get_json()
                # this the team we need to update
                team_key = client.key(constants.teams, int(team_id))
                team = client.get(key=team_key)
                curr_team = team
                if not team:
                    error_404 = {"Error": "No team with this team_id exists"}
                    res = response(error_404, 404)
                    return res
                curr_team["id"] = curr_team.key.id
                # check for name uniqueness
                query = client.query(kind=constants.teams)
                # get results from query
                results = list(query.fetch())
                # update object
                team.update({"name": content["name"], "city": content["city"], "salary_capacity": content["salary_capacity"], "players": curr_team["players"], "owner": curr_team["owner"]})
                client.put(team)
                # add id and url to the team and return it -- wont change the team in data store bc we have used a put
                team["id"] = team.key.id
                team["self"] = request.base_url
                if team["owner"] == jwt:
                    res = make_response(json.dumps(team))
                    res.headers.set('Content-Type', 'application/json')
                    res.status_code = 200
                    # add location header
                    #res.headers['location']= request.base_url
                    return res
                else:
                    # non owner cannot access team
                    res = response({"Error": "Forbidden"},403)
                    return res

            else:
                res = response({"Error": "Unauthorized"}, 401)
                return res
        else:
            res = response({"Error": "Unsupported Media Type"}, 415)
            return res 
    # if team deleted, delete player-team attribute, delete owner-team attribute
    # DELETE -- DONE
    elif request.method == "DELETE":
        if jwt!= "INVALID":
            team_key = client.key(constants.teams, int(team_id))
            team = client.get(key=team_key)
            if team:
                if team["owner"] == jwt:
                    client.delete(team_key)
                    # free up player-teams
                    q = client.query(kind=constants.players)
                    player_res = list(q.fetch())
                    # traverse through list of players
                    for player in player_res:
                        if player["team"] is not None:
                            if player["team"] == team_id:
                                player["team"] = None
                                client.put(player)
                    # free up owner-teams
                    owner_q = client.query(kind=constants.owners)
                    owner_res = list(owner_q.fetch())
                    # traverse through list of owners
                    for owner in owner_res:
                        arr = []
                        # go through all teams that the owner owns 
                        for team in owner["teams"]:
                            if int(team)!= int(team_id):
                                arr.append(team)
                        owner.update({"name": owner["name"], "net_worth": owner["net_worth"], "created_date": owner["created_date"], "unique_id": jwt, "teams": arr})
                        client.put(owner)
                    return ('',204)
                else:
                    # non owner cannot access team
                    res = response({"Error": "Forbidden"},403)
                    return res
            error_404 = {"Error": "No team with this team_id exists"}
            res = response(error_404, 404)
            return res
        else:
            res = response({"Error": "Unauthorized"}, 401)
            return res
    # not the correct url for this method
    else:
        res = response({"Error": "Method Not Allowed"}, 405)
        return res 


# players POST - DONE
@app.route('/players', methods=['POST', 'GET']) # create and view all players
def players_post():
    if request.method == 'POST':
        content_type = request.mimetype
        # checking if request is JSON
        if content_type == "application/json":
            # check the request for 3 attributes
            content = request.get_json()
            obj_name, obj_morale, obj_salary = check_missing_attr_player(content, False, False, False)
            # we do not need to do input validation
            # check if content name is a duplicate
            if obj_name and obj_morale and obj_salary:
                # set up query for data store
                query = client.query(kind=constants.players)
                # get results from query
                results = list(query.fetch())
                # create entity
                new_player = datastore.entity.Entity(key=client.key(constants.players))
                # store the attributes into new entity
                new_player.update({"name": content["name"], "morale": content["morale"],
                "salary": content["salary"], "team": None})
                # put the new player info into our data store
                client.put(new_player)
                new_player["id"] = new_player.key.id
                # put url in this new player -- doesnt change in datastore bc after .put()
                new_player["self"] = request.base_url + "/" + str(new_player.id)
                res = make_response(json.dumps(new_player))
                res.headers.set('Content-Type', 'application/json')
                res.status_code = 201
                return res
            err = {"Error": "The request object is missing at least one of the required attributes."}
            res = response(err, 400)
            return res
        else:
            res = response({"Error": "Unsupported Media Type"}, 415)
            return res

    # view all players
    #GET -- DONE
    elif request.method == 'GET':
        # set up query for data store
        query = client.query(kind=constants.players)
        # start of pagination
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        # if we have this next_page_token then we update for next query
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for player in results:
            player["id"] = player.key.id
            player["self"] =  request.base_url + "/" + str(player.key.id)

        output = {"players": results}
        if next_url:
            output["next"] = next_url
        return (json.dumps(output),200)
    else:
        res = response({"Error": "Method Not Allowed"}, 405)
        return res 

# read, update, delete of CRUD
@app.route('/players/<player_id>', methods=['PATCH', 'PUT', 'DELETE', 'GET'])
def players_find_edit_delete(player_id): 
    #jwt = verify_jwt(request)
    # DONE - GET w/ id 
    if request.method == 'GET':
        accept_headers = request.accept_mimetypes
        # set the id to be the key for client query     
        player_key = client.key(constants.players, int(player_id))
        player = client.get(key=player_key)
        if not player:
            error_404 = {"Error": "No player with this player_id exists"}
            res = response(error_404, 404)
            return res
        # line below might be wrong - check the return of player (might have to make it a list & iterate like in example)
        player["id"] = player.key.id
        # put url in this new obj
        player["self"] = request.base_url
        # client wants response in json format
        if "application/json" in request.accept_mimetypes:
            res = make_response(json.dumps(player))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 200
            return res
        # client wants response in format that server does not support
        else:
            res = response({"Error": "Not Acceptable"}, 406)
            return res
    # PATCH -- DONE 
    elif request.method == "PATCH":
        content_type = request.mimetype
        # checking if request is JSON
        if content_type == "application/json":
            # check the request for 3 attributes
            content = request.get_json()
            # this the player we need to update
            player_key = client.key(constants.players, int(player_id))
            player = client.get(key=player_key)
            curr_player = player
            if not player:
                error_404 = {"Error": "No team with this team_id exists"}
                res = response(error_404, 404)
                return res
            curr_player["id"] = curr_player.key.id
            # check which of 3 attributes are in request:
            missing_name, missing_morale, missing_salary = check_missing_attr_player(content, False, False, False)
            res = response({"Error": "The request object is missing at least one of the required attributes or has an invalid input."}, 400)
            if missing_name and missing_morale and missing_salary:
                # update object
                player.update({"name": content["name"], "morale": content["morale"], "salary": content["salary"], "team": curr_player["team"]})
            elif missing_name and missing_morale:
                # update object
                player.update({"name": content["name"], "morale": content["morale"], "salary": curr_player["salary"], "team": curr_player["team"]})                
            elif missing_morale and missing_salary:
                # update object
                player.update({"name": curr_player["name"], "morale": content["morale"], "salary": content["salary"], "team": curr_player["team"]})  
            elif missing_name and missing_salary:
                # update object
                player.update({"name": content["name"], "morale": curr_player["morale"], "salary": content["salary"], "team": curr_player["team"]})
            elif missing_name:
                # update object
                player.update({"name": content["name"], "morale": curr_player["morale"], "salary": curr_player["salary"], "team": curr_player["team"]})  
            elif missing_morale:
                # update object
                player.update({"name": curr_player["name"], "morale": content["morale"], "salary": curr_player["salary"], "team": curr_player["team"]})  
            elif missing_salary:
                player.update({"name": curr_player["name"], "morale": curr_player["morale"], "salary": content["salary"], "team": curr_player["team"]})
            # add id and url to the player and return it
            client.put(player)
            player["id"] = player.key.id
            player["self"] = request.base_url
            res = make_response(json.dumps(player))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 200
            return res
        else:
            res = response({"Error": "Unsupported Media Type"}, 415)
            return res 
    # PUT -- DONE
    elif request.method == "PUT":
        content_type = request.mimetype
        # checking if request is JSON
        if content_type == "application/json":
            # no input validation -- expected to have all attributes and all of them being correct
            # check the request for 3 attributes
            content = request.get_json()
            # this the player we need to update
            player_key = client.key(constants.players, int(player_id))
            player = client.get(key=player_key)
            curr_player = player
            if not player:
                error_404 = {"Error": "No player with this player_id exists"}
                res = response(error_404, 404)
                return res
            curr_player["id"] = curr_player.key.id
            # check for name uniqueness
            query = client.query(kind=constants.players)
            # get results from query
            results = list(query.fetch())
            # update object
            player.update({"name": content["name"], "morale": content["morale"], "salary": content["salary"], "team": curr_player["team"]})
            client.put(player)
            # add id and url to the player and return it -- wont change the team in data store bc we have used a put
            player["id"] = player.key.id
            player["self"] = request.base_url
            res = make_response(json.dumps(player))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 200
            # add location header
            #res.headers['location']= request.base_url
            return res
        else:
            res = response({"Error": "Unsupported Media Type"}, 415)
            return res 
    # if player deleted, delete player in team's player attribute
    # DELETE -- DONE
    elif request.method == "DELETE":
        player_key = client.key(constants.players, int(player_id))
        player = client.get(key=player_key)
        if player:
            client.delete(player_key)
            # free up player-teams
            q = client.query(kind=constants.teams)
            teams_res = list(q.fetch())
            # traverse through list of players
            for team in teams_res:
                arr = []
                for member in team["players"]:
                    if int(member["id"]) != int(player_id):
                        arr.append(member)
                # update team
                team.update({"name": team["name"], "city": team["city"], "salary_capacity": team["salary_capacity"], "owner": team["owner"], "players": arr})
                client.put(team)
            return ('', 204)
        error_404 = {"Error": "No player with this player_id exists"}
        res = response(error_404, 404)
        return res
    # not the correct url for this method
    else:
        res = response({"Error": "Method Not Allowed"}, 405)
        return res 

@app.route('/owners', methods=['POST', 'GET']) # create and view all teams
def owners_post():
    jwt = verify_jwt(request)
    if request.method == 'POST':
        if jwt != "INVALID":
            content = request.get_json()
            # # set up query for data store
            # query = client.query(kind=constants.owners)
            # # get results from query
            # results = list(query.fetch())
            # # add id to each object
            # for owner in results:
            #     # same user is trying to create a new owner entity, send a 403 error code
            #     if owner["unique_id"] == jwt:
            #         res = response({"Error": "Forbidden"},403)
            #         return res
            # create entity
            new_owner = datastore.entity.Entity(key=client.key(constants.owners))
            # store the attributes into new entity
            #print(type(content))
            #print(content.name, content.net_worth, content.created_date)
            new_owner.update({"name": content["name"], "net_worth": content["net_worth"], "created_date": content["created_date"], "teams":[], "unique_id": jwt})
            # put the new team info into our data store
            client.put(new_owner)
            #print(new_owner)
            new_owner["id"] = new_owner.key.id
            # put url in this new team -- doesnt change in datastore bc after .put()
            new_owner["self"] = request.base_url + "/" + str(new_owner.id)
            res = make_response(json.dumps(new_owner))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 201
            return res
        else:
            res = response({"Error": "Unauthorized"}, 401)
            return res
    elif request.method == 'GET':
        query = client.query(kind=constants.owners)
        results = list(query.fetch())
        #print(results)
        output = []
        for owner in results:
            owner["id"] = owner.key.id
            owner["self"] =  request.base_url + "/" + str(owner.id)
            output.append(owner)
        ans = {"owners": output}
        res = make_response(json.dumps(ans))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 200
        return res
    # not the correct url for this method
    else:
        res = response({"Error": "Method Not Allowed"}, 405)
        return res 

@app.route('/teams/<team_id>/players/<player_id>', methods=['PUT', 'DELETE'])
def teams_put_delete(team_id, player_id):
    jwt = verify_jwt(request)
    # add player to team's players list-- sign player 
    if request.method == "PUT":
        if jwt != "INVALID":
            # player
            player_key = client.key(constants.players, int(player_id))
            player = client.get(key=player_key)
            # team 
            team_key = client.key(constants.teams, int(team_id))
            team = client.get(key=team_key)
            if player and team:
                if team["owner"] == jwt:
                    # success - player team is empty
                    if player["team"] is None:
                        player.update({"name": player["name"], "morale": player["morale"], "salary": player["salary"], "team": team_id})
                        client.put(player)
                        # update teams list to include newly added player
                        t_players = team["players"]
                        t_players.append({"id": player_id})
                        team.update({"name": team["name"], "salary_capacity": team["salary_capacity"], "owner": team["owner"], "city": team["city"], "players": t_players})
                        client.put(team)
                        return ('', 204)
                    error_403 = {"Error": "The player already has a team"}
                    res = response(error_403, 403)
                    return res
                else:
                    error_403 = {"Error": "Forbidden"}
                    res = response(error_403, 403)
                    return res
            # fail - no team or player exists
            error_404 = {"Error": "The specified team and/or player does not exist"}
            res = response(error_404, 404)
            return res
        else:
            res = response({"Error": "Unauthorized"}, 401)
            return res
    # remove player from team -- release player 
    elif request.method == "DELETE":
        if jwt != "INVALID":
            # player
            player_key = client.key(constants.players, int(player_id))
            player = client.get(key=player_key)
            # team 
            team_key = client.key(constants.teams, int(team_id))
            team = client.get(key=team_key)
            # marker to see if player is in array of players for team
            exists = False
            if player and team:
                if team["owner"] == jwt:
                    arr = []
                    for player_m in team["players"]:
                        if int(player_m["id"]) != int(player_id):
                            arr.append(player_m)
                        else:
                            exists = True
                    if exists:
                        # update players in team
                        team.update({"name": team["name"], "salary_capacity": team["salary_capacity"], "owner": team["owner"], "city": team["city"], "players": arr})
                        client.put(team)
                        # set team in player attribute to None
                        player.update({"name": player["name"], "morale": player["morale"], "salary": player["salary"], "team": None})
                        client.put(player)
                        return ('',204)
                    else:
                        error_404 = {"Error": "Team and player ids are valid. However, no player with this player_id in this team given by this team_id"}
                        res = response(error_404, 404) 
                        return res
                else:
                    error_403 = {"Error": "Forbidden"}
                    res = response(error_403, 403)
                    return res   
            # fail - no team or owner exists
            error_404 = {"Error": "The specified team and/or player does not exist"}
            res = response(error_404, 404)
            return res
        else:
            res = response({"Error": "Unauthorized"}, 401)
            return res



if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

