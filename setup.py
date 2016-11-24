from distutils.core import setup

setup(
    name='rPIserver',
    version='1.0',
    packages=[''],
    data_files=[('',['rPIserver.cfg'])],
    url='',
    license='',
    author='X. Mayeur',
    author_email='xavier@mayeur.be',
    description='HTTP server with custom API to control home domotic on Raspberry PI',
    requires=['bottle', 'cherrypy', 'kodipydent', 'oauther', 'configobj', 'fabric']
)
