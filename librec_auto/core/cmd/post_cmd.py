from librec_auto.core.cmd import Cmd
from librec_auto.core.util import Files, utils
from librec_auto.core import ConfigCmd
from pathlib import Path
import os
import sys
import subprocess


class PostCmd(Cmd):

    POST_SCRIPT_PATH = "core/cmd/post"
    POST_ELEM_XPATH = '/librec-auto/post/script'

    def __init__(self):
        self._config = None

    def __str__(self):
        return f'PostCmd()'

    def setup(self, args):
        pass

    def dry_run(self, config):
        self._config = config
        print (f'librec-auto (DR): Running post command {self}')

        post_elems = config.get_xml().xpath(self.POST_ELEM_XPATH)

        for post_elem in post_elems:
            param_spec = utils.create_param_spec(post_elem)
            script_path = utils.get_script_path(post_elem, 'post')

            print (f'\tPost script: {script_path}')
            print (f'\tParameters: {param_spec}')

    def execute(self, config: ConfigCmd):
        self._config = config
        self.status = Cmd.STATUS_INPROC
        files = config.get_files()

        target = files.get_exp_path()

        post_path = files.get_post_path()

        if not post_path.exists():
            print('librec-auto: post directory missing. Creating. ', target)
            os.makedirs(str(post_path))

        post_elems = config.get_xml().xpath(self.POST_ELEM_XPATH)

        for post_elem in post_elems:
            param_spec = utils.create_param_spec(post_elem)
            script_path = utils.get_script_path(post_elem, 'post')

            proc_spec = [sys.executable, script_path.absolute().as_posix(),
                         self._config.get_files().get_config_path().name,
                         config.get_target()] + param_spec
            print (f'librec-auto: Running post-processing script {proc_spec}')
            subprocess.call(proc_spec)