from datetime import datetime
from functools import partial

from config import assets
from utils.utils import *
from sanic import Sanic
from sanic.response import json as sanic_json
from sanic_cors import CORS, cross_origin
from config.config import get_config
from vulnerability_scanner import vaaas
from sanic_openapi import doc, swagger_blueprint
from apscheduler.schedulers.background import BackgroundScheduler

log = MyLogger(logger_name=__name__).get_logger()
_conf = get_config()
app = Sanic(__name__)
app.blueprint(swagger_blueprint)
app.config['CORS_AUTOMATIC_OPTIONS'] = True
app.config['REQUEST_TIMEOUT'] = 60
# app.config['RESPONSE_TIMEOUT'] = 60
app.config['CORS_HEADERS'] = 'Content-Type,Authorization'
CORS(app)
assets.init()
scheduler = BackgroundScheduler()  # task scheduler
scheduler.start()
assets.set_asset('scheduler', scheduler)
scanner = vaaas.Vaaas()


@app.route('/health', methods=['GET'])
@doc.description('Check the health status of the API')
@doc.response(200, {'result': str})
async def home(request):
    return sanic_json({'result': 'This is the vulnerability assessment as a service component'}, status=200)


@app.post('/tasks/start')  # TODO check if task name exists
@doc.description('Initiates a scan on a specified target e.g., method=POST url= /tasks/start body= {"target":127.0.0.1" (ip or network), "speed":3 (*optional values: 1-5)}')
@doc.consumes({'target': {"name": str, "target": str, 'speed': int}}, location='body')
@doc.response(200, {'result': str, 'more': str})
async def task_start(request):
    """
    :param request: {"target":string "127.0.0.1" OR "192.168.1.0/24", "speed":int (1-5)}
    :return:
    """
    try:
        result = None
        if request.method == 'POST':
            payload = json.loads(request.body)
            print(payload)
            assert payload.get('name'), Exception('Missing "name" in request')
            assert payload.get('target'), Exception('Missing "target" in request')
            # result = scanner.scan_network(_name=payload.get('name'), _net=payload.get('target'), speed=payload.get('speed'), script=payload.get('script'))
            _job = scheduler.add_job(func=partial(scanner.scan_network, _name=payload.get('name'), _net=payload.get('target'), speed=payload.get('speed'), script=payload.get('script')),
                                     trigger='date', next_run_time=datetime.now())
            result = {'result': 'SCAN_NETWORK_STARTED', 'more': f"'Started VaaaS job for target: {payload.get('target')}'"}
        return sanic_json(result, status=200)
    except Exception as e:
        return sanic_json({'error': e.__str__()}, status=501)


@app.post('/reports')
@doc.description('Returns the reports for a specified target e.g., method=POST url= /reports body= {"target":127.0.0.1"}')
@doc.consumes({'target': {"name": str}}, location='body')
@doc.response(200, {'result': str, 'items': {'reports': dict}})
async def reports(request):
    """
    :param request: {"target":string} | "127.0.0.1" OR "192.168.1.0/24"
    :return:
    """
    try:
        result = None
        if request.method == 'POST':
            assert json.loads(request.body), Exception('Body is either empty or not Json Serializable')
            payload = json.loads(request.body if request.body else {})
            result = scanner.get_task_reports(payload['name'])
        return sanic_json(result, status=200)
    except Exception as e:
        return sanic_json({'error': e.__str__()}, status=501)


@app.get('/reports')
@doc.description('Returns all existing reports ')
@doc.response(200, {'result': str, 'items': {'reports': list}})
async def get_all_reports(request):
    """
    :param request: {"target":string} | "127.0.0.1" OR "192.168.1.0/24"
    :return:
    """
    try:
        result = None
        if request.method == 'GET':
            result = scanner.get_all_reports()
        return sanic_json(result, status=200)
    except Exception as e:
        return sanic_json({'error': e.__str__()}, status=501)


@app.post('/reports/stix')
@doc.description('Returns the reports of a target in STIX2.0 format e.g., method=POST url= /reports/stix body= {"report":{...}"}')
@doc.consumes({'target': {"report": dict}}, location='body')
@doc.response(200, {'result': str, 'items': {'report': dict}})
async def get_stix_report(request):
    """
    :param
    :return:
    """
    try:
        result = None
        if request.method == 'POST':
            payload = json.loads(request.body)
            result = scanner.parse_report_to_stix(payload)
        return sanic_json(result, status=200)
    except Exception as e:
        return sanic_json({'error': e.__str__()}, status=501)


# @app.get(root_path + '/reports')
# @doc.description('Returns all reports')
# @doc.response(200, {'result': str, 'items': dict})
# async def reports(request):
#     """
#     :param request: None
#     :return: {"result"="GET_ALL_REPORTS_SUCCESS", "items"={"reports":[report]}
#     """
#     try:
#         result = None
#         if request.method == 'GET':
#             pass  # TODO add proper function
#         return sanic_json(result, status=200)
#     except Exception as e:
#         return sanic_json({'error': e.__str__()}, status=501)


@app.get('/tasks')
@doc.description('Returns all tasks')
@doc.response(200, {'result': str, 'items': {'tasks': dict}})
async def get_tasks(request):
    """
    :param request: None
    :return: {"result"="GET_ALL_TASKS_SUCCESS", "items"={"tasks":{}}"}}
    """
    try:
        result = None
        if request.method == 'GET':
            result = scanner.get_all_tasks()
        return sanic_json(result, status=200)
    except Exception as e:
        return sanic_json({'error': e.__str__()}, status=501)


@app.post('/tasks')
@doc.description('Returns specific task')
@doc.consumes({'target': {"name": str}}, location='body')
@doc.response(200, {'result': str, 'items': {'task': dict}})
async def get_one_task(request):
    """
    :param request: None
    :return: {"result"="GET_TASK_SUCCESS", "items"={"task":{}}"}}
    """
    try:
        result = None
        if request.method == 'POST':
            payload = json.loads(request.body)
            result = scanner.get_task(payload['name'])
        return sanic_json(result, status=200)
    except Exception as e:
        return sanic_json({'error': e.__str__()}, status=501)


@app.post('/tasks/progress')
@doc.description('Returns a specific task\'s progress')
@doc.consumes({'target': {"name": str}}, location='body')
@doc.response(200, {'result': str, 'items': {'processes': dict}})
async def task_progress(request):
    """
    :param request: None
    :return: {"result"=string, "items"={"processes":{}}"}}
    """
    try:
        result = None
        if request.method == 'POST':
            payload = json.loads(request.body)
            result = scanner.get_task_progress(payload['name'])
        return sanic_json(result, status=200)
    except Exception as e:
        return sanic_json({'error': e.__str__()}, status=501)


@app.delete('/tasks/<task_name:string>')
@doc.description('Deletes a specific task, by task-name')
@doc.response(200, {'result': str, 'more': str})
async def delete_task(request, task_name):
    """
    :param task_name: string (URL)
    :return: {"result"=string, "items"={"processes":{}}"}}
    """
    try:
        result = None
        if request.method == 'DELETE':
            assert task_name, Exception('must include task name in the path')
            result = scanner.delete_task(task_name)
        return sanic_json(result, status=int(result['status_code']))
    except Exception as e:
        return sanic_json({'error': e.__str__()}, status=501)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8003)
