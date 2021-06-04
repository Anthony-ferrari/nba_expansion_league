import json
from flask import make_response
# helper  - boats
def response(objecto, status_code):
    res = make_response(json.dumps(objecto))
    res.status_code = status_code
    res.headers.set('Content-Type', 'application/json')
    return res


def check_missing_attr(req_content, m_name, m_city, m_salary_capacity):
    #print(req_content.keys())
    for attribute in req_content.keys():
        if attribute == "name":
            #print("name")
            m_name = True
        elif attribute == "city":
            #print("city")
            m_city = True
        elif attribute == "salary_capacity":
            #print("salary_capacity")
            m_salary_capacity = True
    return m_name, m_city, m_salary_capacity

def check_missing_attr_player(req_content, m_name, m_morale, m_salary):
    for attribute in req_content.keys():
        if attribute == "name":
            m_name = True
        elif attribute == "morale":
            m_morale = True
        elif attribute == "salary":
            m_salary = True
    return m_name, m_morale, m_salary