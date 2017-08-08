import glob2
from optparse import OptionParser
import os
from os.path import join
import signal
from subprocess import PIPE, Popen
import sys
from time import gmtime, strftime

BASH_EXE = "/bin/bash"

bash_process = None


# noinspection PyUnusedLocal
def signal_handler(signal_param, frame_param):
    if bash_process:
        bash_process.kill()
        print('Killed GSTP test execution process')
    sys.exit(0)


def main():
    parser = OptionParser()
    parser.add_option("-i", "--inputFolder", dest="input_folder", default="",
                      help="Folder containing scripts to run")
    parser.add_option("-l", "--logFolder", dest="log_folder", default="",
                      help="Folder containing logs to move")
    parser.add_option("-d", "--destLogFolder", dest="dest_log_folder", default="",
                      help="Folder containing logs to move")
    parser.add_option("-p", "--product", dest="product", default="",
                      help="Short name of product under test (for use in naming relocated log folders)")

    (options, args) = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)
    global bash_process

    log_folder = options.log_folder
    orig_dest_log_folder = options.dest_log_folder
    product = options.product

    if os.path.isfile(os.path.join(log_folder, 'artifacts.csv')):
        os.remove(os.path.join(log_folder, 'artifacts.csv'))
    if os.path.isfile(os.path.join(log_folder, 'results.csv')):
        os.remove(os.path.join(log_folder, 'results.csv'))
    if os.path.isfile(os.path.join(log_folder, 'client.txt')):
        os.remove(os.path.join(log_folder, 'client.txt'))
    if os.path.isfile(os.path.join(log_folder, 'validation_failures.txt')):
        os.remove(os.path.join(log_folder, 'validation_failures.txt'))
    if os.path.isfile(os.path.join(log_folder, 'profile_failures.txt')):
        os.remove(os.path.join(log_folder, 'profile_failures.txt'))

    if options.input_folder:
        only_files = glob2.glob(options.input_folder + '/*.sh')

        for filename in only_files:
            t = strftime("%Y%m%d%H%M%S", gmtime())
            print("Started " + filename + " at " + t)

            bash_command = BASH_EXE + " " + join(options.input_folder, filename)
            bash_process = Popen(bash_command, shell=True, stdout=PIPE)
            bash_process.wait()

            # noinspection PyUnusedLocal
            process = None

            dest_log_folder = os.path.join(orig_dest_log_folder, product + "_" +
                                           os.path.splitext(os.path.basename(filename))[0] + "_" + t)
            os.mkdir(dest_log_folder)
            if os.path.isfile(os.path.join(log_folder, 'artifacts.csv')):
                os.rename(os.path.join(log_folder, 'artifacts.csv'), os.path.join(dest_log_folder, 'artifacts.csv'))
            if os.path.isfile(os.path.join(log_folder, 'results.csv')):
                os.rename(os.path.join(log_folder, 'results.csv'), os.path.join(dest_log_folder, 'results.csv'))

            art_files = glob2.glob(options.log_folder + '/artifacts*.csv')
            for art in art_files:
                if os.path.isfile(art):
                    os.rename(art, os.path.join(dest_log_folder, os.path.basename(art)))

            res_files = glob2.glob(options.log_folder + '/results*.csv')
            for res in res_files:
                if os.path.isfile(res):
                    os.rename(res, os.path.join(dest_log_folder, os.path.basename(res)))

            if os.path.isfile(os.path.join(log_folder, 'client.txt')):
                os.rename(os.path.join(log_folder, 'client.txt'), os.path.join(dest_log_folder, 'client.txt'))
            if os.path.isfile(os.path.join(log_folder, 'debug.txt')):
                os.rename(os.path.join(log_folder, 'debug.txt'), os.path.join(dest_log_folder, 'debug.txt'))
            if os.path.isfile(os.path.join(log_folder, 'validation_failures.txt')):
                os.rename(os.path.join(log_folder, 'validation_failures.txt'), os.path.join(dest_log_folder,
                                                                                            'validation_failures.txt'))
            if os.path.isfile(os.path.join(log_folder, 'profile_failures.txt')):
                os.rename(os.path.join(log_folder, 'profile_failures.txt'), os.path.join(dest_log_folder,
                                                                                         'profile_failures.txt'))

            t2 = strftime("%Y%m%d%H%M%S", gmtime())
            print("Completed " + filename + " at " + t2)


if __name__ == '__main__':
    main()
