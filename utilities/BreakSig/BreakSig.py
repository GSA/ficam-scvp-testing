__author__ = 'cwallace'

import glob2
from optparse import OptionParser
import os
from subprocess import PIPE, Popen, call
from shutil import copyfile

OPENSSL_EXE = "/usr/bin/openssl"

broken_signatures = ['BadSignedCACert.crt','InvalidEESignatureTest3EE.crt']
broken_crl_signatures = ['BadCRLSignatureCACRL.crl']

def main():
    parser = OptionParser()
    parser.add_option("-i", "--inputFolder", dest="input_folder", default="",
                      help="Folder containing at least the three files that require broken signatures")

    (options, args) = parser.parse_args()

    if options.input_folder:
        orig_cert_files = glob2.glob(options.input_folder + '/*.crt')
        orig_crl_files = glob2.glob(options.input_folder + '/*.crl')

        for filename in orig_cert_files:
            orig_name = os.path.basename(filename)

            if orig_name in broken_signatures:
                with open(filename, mode='rb') as file:
                    fileContent = bytearray(file.read())
                    num_bytes = len(fileContent)
                    if fileContent[num_bytes-1] == 0xFF:
                        fileContent[num_bytes-1] = 0xFE
                    else:
                        fileContent[num_bytes-1] = 0xFF
                    file.close()
                    fw = open(filename, mode='wb')
                    fw.write(fileContent)
                    fw.close()

            if 'BadSignedCACert.crt' == orig_name:
                print("Outputting P7 with bad CA signature cert - move this into Hosts folder manually")
                openssl_command = OPENSSL_EXE + " x509 -inform DER -outform PEM -in " + filename + " -out " + filename + '.pem'
                p = Popen(openssl_command, shell=True, stdout=PIPE)
                p.wait()

                p7_filename = filename.replace("crt", "p7b")
                openssl_command = OPENSSL_EXE + " crl2pkcs7 -nocrl -outform DER -certfile " + filename + '.pem' + " -out " + p7_filename
                p = Popen(openssl_command, shell=True, stdout=PIPE)
                p.wait()


        for filename in orig_crl_files:
            orig_name = os.path.basename(filename)

            if orig_name in broken_crl_signatures:
                with open(filename, mode='rb') as file:
                    fileContent = bytearray(file.read())
                    num_bytes = len(fileContent)
                    if fileContent[num_bytes-1] == 0xFF:
                        fileContent[num_bytes-1] = 0xFE
                    else:
                        fileContent[num_bytes-1] = 0xFF
                    file.close()
                    fw = open(filename, mode='wb')
                    fw.write(fileContent)
                    fw.close()


if __name__ == '__main__':
    main()