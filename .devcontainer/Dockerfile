FROM mcr.microsoft.com/devcontainers/python:1-3.9-bullseye

ENV PYTHONUNBUFFERED 1

RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall \
    && chmod 755 /tmp/msfinstall \
    && /tmp/msfinstall

ENV PYTHONPATH=/opt/metasploit-framework/embedded/framework/lib/msf/core/modules/external/python:/usr/local/python/current
RUN pip3 install requests