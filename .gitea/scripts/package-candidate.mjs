import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {existsSync,mkdirSync,readFileSync,writeFileSync} from 'node:fs';

assert.equal(process.env.GITHUB_SERVER_URL,'http://192.168.1.130:3000');
assert.equal(process.env.GITHUB_REPOSITORY,'hallyaus/SecretSentry');
assert.equal(process.env.GITHUB_REF,'refs/heads/main');
const source=process.env.GITHUB_SHA;
assert.match(source??'',/^[a-f0-9]{40}$/);
const git=(...args)=>execFileSync('git',args,{encoding:'utf8'}).trim();
assert.equal(git('rev-parse','HEAD'),source);
const component='custom_components/secretsentry';
const manifest=JSON.parse(readFileSync(component+'/manifest.json','utf8'));
assert.equal(manifest.domain,'secretsentry');
assert.match(manifest.version,/^\d+\.\d+\.\d+$/);
const hacs=JSON.parse(readFileSync('hacs.json','utf8'));
assert.ok(hacs.zip_release!==true&&!('filename' in hacs),'Keep the existing source-archive HACS distribution contract');
const members=[component,'hacs.json','README.md','LICENSE'].filter(path=>existsSync(path));
const paths=git('ls-tree','-r','--name-only',source,'--',...members).split('\n');
assert.ok(paths.length>5);
for(const path of paths){
 assert.ok(path.startsWith(component+'/')||members.slice(1).includes(path));
 assert.ok(!path.split('/').some(part=>part==='..'||part.startsWith('.env')||part==='__pycache__'));
}
mkdirSync('private-source-candidate');
const archive='private-source-candidate/personal-integration-source.zip';
execFileSync('git',['archive','--format=zip','--output='+archive,source,'--',...members]);
const bytes=readFileSync(archive);assert.ok(bytes.length>0&&bytes.length<20*1024*1024);
const receipt={repository:'hallyaus/SecretSentry',source,run:process.env.GITHUB_RUN_ID,
 source_tree:git('rev-parse',source+'^{tree}'),component_tree:git('rev-parse',source+':'+component),
 version:manifest.version,members:paths,sha256:createHash('sha256').update(bytes).digest('hex'),
 published:false,installed:false,release_approved:false,hacs_validation_required_separately:true,
 physical_device_or_account_requests:0};
writeFileSync('private-source-candidate/source-provenance.json',JSON.stringify(receipt,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({...receipt,members:paths.length}));
