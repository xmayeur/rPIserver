import os.path
from py_compile import compile
from time import sleep

from fabric.api import *

# from fabric.contrib.project import rsync_project as rsync


env.host_string = 'rpiMON'
env.user = 'pi'
env.use_ssh_config = True

# Deploy files
deploy_list = ['rPIserver.py', 'tdtool.py', 'cacert.pem', 'home.mayeur.be.crt', 'home.mayeur.be.pem', 'rPIserver.cfg']
project = 'rPIserver'
config = project + '.conf'
cd
for f in deploy_list:
    if f.find('.py') > 0:
        compile(f)
        put(local_path=f + 'c', remote_path='~/'+project+'/'+ f + 'c', use_sudo=True, mode=0755)
    else:
        put(local_path=f, remote_path='~/'+project+'/'+ f , use_sudo=True, mode=0755)

put (local_path='wifi_rebooter.sh', remote_path='/usr/local/bin/checkwifi.sh' , use_sudo=True, mode=0755)

# Stop service, update it and re-start
with settings(warn_only=True):
    run('sudo service ' + project + ' stop')

with cd('/etc/init.d'):
    put(local_path=project + '.', remote_path=os.path.join('/etc/init.d/', project), use_sudo=True, mode=0755)
    run('sudo update-rc.d ' + project + ' defaults')

run('sudo service ' + project + ' start')
sleep(5)
run('sudo service ' + project + ' status')
