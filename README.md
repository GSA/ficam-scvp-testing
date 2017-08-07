# ficam-scvp-testing

Usage guides are available in the docs folders of this repository. The easiest way to get started after configuring the artifacts VM is to download the tools VM, which contains a variety of materials in the home directory of the default pcpadmin user. To configure the SCVP client to reference your responder, add the signing key of the responder to the key store located at ~/scvp-client/vssTrustStore.jks. Next, edit the ~/scvp-client/vss.properties file to identify the alias of the key just added to the key store as well as the URL of the SCVP interface in the VSS_TRUSTSTORE_SCVP_SIGNER_ISSUER_LABEL and VSS_SCVP_SERVER_URI fields.

A full set of scripts are provided in `~/scvp-client/pre-generated-scripts` folder. To run these, use the `GSTPScriptRunner` utility as follows:

```
$ source ~/scvp-client/venv-scvp-client/bin/activate
$ python GSTPScriptRunner.py -i /home/pcpadmin/scvp-client/pregenerated-scripts -l ${SCVP_OUTPUT_PATH} -p HID -d /home/pcpadmin/Desktop/ResponderLogs
```

This command assumes you have created a folder on the desktop to receive sorted copies of logs and have created a folder to receive working logs and saved that to the `SCVP_OUTPUT_PATH` environment variable.

If you would like to use the provided `PITTv2` utility to test your artifacts VM, update the `/etc/hosts` file to reference your VM.
