import argparse
from pathlib import Path

from librec_auto import read_config_file
from librec_auto.util import Files
from librec_auto.cmd import Cmd, SequenceCmd, PurgeCmd, LibrecCmd, PostCmd, RerankCmd, StatusCmd, ParallelCmd
import logging


def read_args():
    '''
    Parse command line arguments.
    :return:
    '''
    parser = argparse.ArgumentParser(description='The librec-auto tool for running recommender systems experiments')
    parser.add_argument('action',choices=['run','split', 'eval', 'rerank', 'post', 'purge', 'status', 'describe'])

    parser.add_argument("target", help="Path to experiment directory")

    # Optional with arguments
    # parser.add_argument("-ex","--exhome", help="stub")
    # parser.add_argument("-rs","--reset", help = "stub")
    # parser.add_argument("-rss","--revise-step", help="stub")
    parser.add_argument("-c", "--conf", help="Use the specified configuration file")

    # Flags
    parser.add_argument("-dr","--dry_run",
                        help = "Show sequence of command execution but do not execute commands",
                        action ="store_true")
    parser.add_argument("-q","--quiet",
                        help = "Skip confirmation when purging",action ="store_true")
    parser.add_argument("-np","--no_parallel",
                        help = "Ignore thread-count directive and run all operations sequentially",
                        action ="store_true")
    parser.add_argument("-p", "--purge",
                        help="Purge results of step given in <option> and all subsequent steps",
                        choices=['all', 'split', 'results', 'rerank', 'post'], default='all')
    parser.add_argument("-nc", "--no_cache",
                        help="Do not cache any intermediate results (Not implemented)",
                        action="store_true")

    input_args = parser.parse_args()
    return vars(input_args)


def load_config(args):

    config_file =  Files.DEFAULT_CONFIG_FILENAME

    if args['conf']:      # User requested a different configuration file
        config_file = args['conf']

    target = args['target']

    return read_config_file(config_file, target)


DESCRIBE_TEXT = 'Librec-auto automates recommender systems experimentation using the LibRec Java library.\n' +\
    '\tA librec-auto experiment consist of five steps governed by the specifications in the configuration file:\n' +\
    '\t- split: Create training / test splits from a data set. (LibRec)\n'+\
    '\t- exp: Run an experiment generating recommendations for a test set (LibRec)\n' +\
    '\t- rerank (optional): Re-rank the results of the experiment (script)\n' +\
    '\t- eval: Evaluate the results of a recommendation experiment (LibRec)\n' +\
    '\t- post (optional): Perform post-processing computations (script)\n' + \
    'Steps labeled LibRec are performed by the LibRec library using configuration properties generated by librec-auto.\n' +\
    'Steps labeled script are performed by experimenter-defined scripts.\n' + \
    'Run librec_auto describe <step> for additional information about each option.'

DESCRIBE_DICT = {
    'run': 'Run a complete librec-auto experiment. Re-uses cached results if any. \
May result in no action if all computations are up-to-date and no purge option is specified.',
    'split': 'Run the training / test split only',
    'exp': 'Run the experiment, re-ranking, evaluation, and post-processing',
    'rerank': 'Run the re-ranking, evaluation and post-processing',
    'eval' : 'Run the evaluation and post-processing',
    'post': 'Run post-processing steps',
    'purge': 'Purge cached computations. Uses -p flag to determine what to purge',
    'status': 'Print out the status of the experiments'
}


def print_description(args):
    act = args['target']
    if act in DESCRIBE_DICT:
        print (f'librec_auto {act} <target>: {DESCRIBE_DICT[act]}')
    else:
        print(DESCRIBE_TEXT)


def purge_type (args):
    if 'purge' in args:
        return args['purge']
    # If no type specified and you're purging, purge everything
    elif args['action']=='purge':
        return 'split'
    else:
        return 'none'


def build_librec_commands(librec_action, args, config):
    librec_commands = [LibrecCmd(librec_action, i) for i in range(config.get_sub_exp_count())]
    threads = 1
    if 'rec.thread.count' in config.get_prop_dict():
        threads = int(config.get_prop_dict()['rec.thread.count'])

    if threads > 1 and not args['no_parallel']:
        return ParallelCmd(librec_commands, threads)
    else:
        return SequenceCmd(librec_commands)

# The purge rule is: if the command says to run step X, purge the results of X and everything after.
def setup_commands (args, config):
    action = args['action']
    purge_noask = args['quiet']

    # Create flags for optional steps
    rerank_flag = False
    if config.get_unparsed('rerank') is not None:
        rerank_flag = True

    post_flag = False
    if config.get_unparsed('post') is not None:
        post_flag = True

    # Purge files (possibly) from splits and subexperiments
    if action == 'purge':
        cmd = PurgeCmd(purge_type(args), noask=purge_noask)
        return cmd

    # Shows the status of the experiment
    if action == 'status':
        cmd = StatusCmd()
        return cmd

    # Perform (only) post-processing on results
    if action == 'post' and post_flag:
        cmd = PostCmd()
        return cmd
    # No post scripts available
    if action == 'post' and not post_flag:
        logging.warning("No post-processing scripts available for post command.")
        return None

    # Perform re-ranking on results, followed by evaluation and post-processing
    if action == 'rerank' and rerank_flag: # Runs a reranking script on the python side
        cmd1 = PurgeCmd('rerank', noask=purge_noask)
        cmd2 = RerankCmd()
        cmd3 = build_librec_commands('eval', args, config)
        cmd = SequenceCmd([cmd1, cmd2, cmd3])
        if post_flag:
            cmd.add_command(PostCmd())
        return cmd
    # No re-ranker available
    if action == 'rerank' and not rerank_flag:
        logging.warning("No re-ranker available for rerank command.")
        return None

    # LibRec actions
    # re-run splits only
    if action == 'split':
        cmd1 = PurgeCmd('split', noask=purge_noask)
        cmd2 = build_librec_commands('split', args, config)
        cmd = SequenceCmd([cmd1, cmd2])
        return cmd

    # re-run experiment and continue
    if action== 'run':
        cmd1 = PurgeCmd('results', noask=purge_noask)
        cmd2 = build_librec_commands('full', args, config)
        cmd = SequenceCmd([cmd1, cmd2])
        if rerank_flag:
            cmd.add_command(RerankCmd())
        if post_flag:
            cmd.add_command(PostCmd())
        return cmd

    # eval-only
    if action == 'eval':
        cmd1 = PurgeCmd('post', noask=purge_noask)
        cmd2 = build_librec_commands('eval', args, config)
        cmd = SequenceCmd([cmd1, cmd2])
        if post_flag:
            cmd.add_command(PostCmd())
        return cmd


# -------------------------------------


if __name__ == '__main__':
    args = read_args()

    if args['action']=='describe':
        print_description(args)
    else:
        config = load_config(args)

        if len(config.get_prop_dict()) > 0:
            command = setup_commands(args, config)
            if isinstance(command, Cmd):
                if args['dry_run']:
                    command.dry_run(config)
                else:
                    command.execute(config)
            else:
                logging.error("Command instantiation failed.")
        else:
            logging.error("Configuration loading failed.")
