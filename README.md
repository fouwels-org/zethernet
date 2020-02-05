# Instructions 
- cd to $WORKSPACE
- clone zeek 3.0.1 (`git clone --recursive --branch v3.0.1 https://github.com/zeek/zeek`)
- build zeek `./configure --engine=Ninja` && `ninja -C build`
- cd to $WORKSPACE/zeek/src/analyzer/protocol
- clone this repo
- open this repo in vscode
- includes will now resolve 