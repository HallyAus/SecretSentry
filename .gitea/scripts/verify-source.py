"""Parse tracked source without importing the integration or reading host configuration."""
import ast,json,pathlib,subprocess
paths=subprocess.check_output(['git','ls-files','-z'],text=True,encoding='utf-8').split('\0')
python_files=json_files=0
for name in filter(None,paths):
 path=pathlib.Path(name)
 if name.endswith('.py'):
  ast.parse(path.read_text(encoding='utf-8'),filename=name);python_files+=1
 elif name.endswith('.json'):
  json.loads(path.read_text(encoding='utf-8'));json_files+=1
manifest=json.loads(pathlib.Path('custom_components/secretsentry/manifest.json').read_text(encoding='utf-8'))
assert manifest['domain']=='secretsentry' and manifest.get('version')
print(json.dumps({'tracked_python_files_parsed':python_files,'tracked_json_files_parsed':json_files,'integration_imported':False,'provider_requests':0}))
