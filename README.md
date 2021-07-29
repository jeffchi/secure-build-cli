# IBM Cloud Hyper Protect Virtual Servers Secure Build Server

IBM Cloud Hyper Protect Virtual Servers Secure Build Server, also referred to as Secure Build Server (SBS) allows you to build a trusted container image within a secure enclave, provided by [IBM Cloud Hyper Protect Virtual Servers](https://cloud.ibm.com/catalog/services/hyper-protect-virtual-server). The enclave is highly isolated - developers can access the container only by using a specific API and the cloud administrator cannot access the contents of the container as well, thereby the created image can be highly trusted. Specifically, the build server cryptographically signs the image, and a manifest (which is a collection of materials used during the build for audit purposes). Since the enclave protects signing keys inside the enclave, the signatures can be used to verify whether the image and manifest are from the build server, and not somewhere else.

The following diagram illustrates a high level structure of SBS, which is provisioned by an administrator by using the [IBM Cloud CLI](https://cloud.ibm.com/docs/cli?topic=hpvs-cli-plugin-hpvs_cli_plugin). This document describes how a developer can interact with the server by using the `build.py` script. A developer prepares the source code of an application with Dockerfile, in a source code repository such as GitHub. The build server pulls the source code, builds a container image by using the Dockerfile, signs it, and pushes it to a container registry, such as Docker Hub. During the build process, it also creates a manifest file and signs it. Optionally, it can
push the manifest to Cloud Object Storage, or the developer can download it on a local file system. The build server can also export and import its state as a single file, which includes signing keys of the image and manifest, with build parameters. When exported, the state is encrypted in such a way that the developer or IBM cannot decrypt the state image outside the enclave. It can be decrypted only inside the enclave. The encrypted state image can be pushed to Cloud Object Storage, or the developer can download it on a local file system.

<p align="center">
  <img src="./images/secure-build.png">
</p>

<!--
Secure Build Service is basically used to build and sign docker images where signing key will be secure. No one can see signing private key. Even image builder can not see the signing private key.
-->

## Before you begin

The following is a list of hardware or software requirements:
- Linux management server from where you can run the build CLI tool (Linux workstation or VM).
  - x86 architecture (recommended 2 CPUs/4GB memory or more)
  - Ubuntu 18.04 or 16.04 (64 bit)
  - Python 3.6 (Python 2.x is not supported)
- Access to GitHub for hosting the source code.
- Dockerfile (everything that you need to build your container image).
- Access to IBM Cloud Registry or DockerHub.
- (Optional) Access to IBM Cloud Object Storage (COS) Service.
- Access to IBM Hyper Protect Virtual Servers.
- Registration definition file of Secure Build Server (secure_build.asc) from [IBM Cloud Docs](https://cloud.ibm.com/docs/hp-virtual-servers?topic=hp-virtual-servers-imagebuild).


## Install the CLI
The CLI script is written in Python and has been tested using Python 3.6.9. You must install Python3 and pip3, if you don't have them on your client system. The build.py is the main script that comes with secure-build-cli. This script helps you to interact and do the required operations on the SBS instance after it is created by using the IBM Cloud CLI. For systems that run Ubuntu, you can run the following commands to install them.
```
apt-get update
apt-get install python3 python3-pip
python3 -m pip install -U pip
```

After you run the commands listed above, clone the repository, and install the dependencies by running the following commands:

```
git clone git@github.com:ibm-hyper-protect/secure-build-cli.git
cd secure-build-cli
pip3 install -r requirements.txt
```

## Preparing the configuration
Create the `sbs-config.json` file in any location you choose on your local machine, and add the following content in the file:
```
{
  "CICD_PUBLIC_IP": "",
  "CICD_PORT": "443",
  "IMAGE_TAG": "",
  "GITHUB_KEY_FILE": "~/.ssh/id_rsa",
  "GITHUB_URL": "git@github.com:<git_user>/<git_repo>.git",
  "GITHUB_BRANCH": "master",
  "CONTAINER_NAME": "SBContainer",
  "REPO_ID": "sbs",
  "DOCKER_REPO": "<docker_namespace>/<docker_repository_name>",
  "DOCKER_USER": "<docker_user>",
  "DOCKER_PASSWORD": "<docker_password>",
  "IMAGE_TAG_PREFIX": "<docker_image_tag>",
  "DOCKER_CONTENT_TRUST_BASE": "False",
  "DOCKER_CONTENT_TRUST_BASE_SERVER": "",
  "DOCKER_RO_USER": "<docker_user>",
  "DOCKER_RO_PASSWORD": "<docker_password>",
  "ENV_WHITELIST":  ["<KEY1>", "<KEY2>"],
  "ARG": {
    "<BUILD_ARG1>": "<VALUE1>",
    "<BUILD_ARG2>": "<VALUE2>"
  }
}
```

Where
```
CICD_PUBLIC_IP - IP address of the SBS server. Leave it as "" since it is unknown until the server is provisioned.
CICD_PORT - port on which a build service is running (default: 443).
IMAGE_TAG - image tag of the container image to be deployed as SBS server. Use "1.3.0.1" unless otherwise noted.
GITHUB_KEY_FILE - Private key path to access your GitHub repo.
GITHUB_URL - GitHub URL.
GITHUB_BRANCH - GitHub branch name.
CONTAINER_NAME - Name of the Hyper Protect Virtual Servers instance which you want to create on cloud. This name can be different from the name which you use on cloud. The name is used as a part of a certificate file name. You can choose any valid string as a file name.
REPO_ID - This is the ID which is used as a prefix of the registration definition file for a newly built image.
DOCKER_REPO - DockerHub repository.
DOCKER_USER - docker user name who has write access to above repository.
DOCKER_PASSWORD - docker password who has write access to above repository.
IMAGE_TAG_PREFIX - a prefix of the image tag for the image to be built. The full image tag will be IMAGE_TAG_PREFIX + '-' + the leading seven digits from the GitHub repository hash.
DOCKER_CONTENT_TRUST_BASE - If your base image that is mentioned in the Dockerfile is signed, then make it true.
DOCKER_CONTENT_TRUST_BASE_SERVER - If your base image mentioned in the Dockerfile is signed, then you can specify the notary URL (default: https://notary.docker.io).
DOCKER_RO_USER - you can use the same as DOCKER_USER. It is recommended that you specify a user who has read access only to your Docker repository.
DOCKER_RO_PASSWORD - you can use same as DOCKER_PASSWORD. It is recommended that you specify a user who has read access only to your Docker repository.
ENV_WHITELIST - All environment variable names need to be listed. The Hyper Protect Virtual Servers don't allow any environment variable unless it is in this list because of a security reason.
ARG - You have to pass all build argument parameters as you pass during Docker build.
```

Note: - If you use IBM Cloud Registry instead of DockerHub registry, then you must use the following parameters:

```buildoutcfg
"DOCKER_BASE_SERVER": "<domain_name>",
"DOCKER_PUSH_SERVER": "<domain_name>",
"DOCKER_USER": "iamapikey",
"DOCKER_PASSWORD": "<ibm_cloud_apikey>"
"DOCKER_RO_USER": "iamapikey",
"DOCKER_RO_PASSWORD": "<ibm_cloud_apikey>",
"DOCKER_CONTENT_TRUST_PUSH_SERVER": "https://<domain_name>:4443",
```
The `<domain_name>` specifies the location of IBM Cloud Container Registry (e.g. `us.icr.io`). Select the domain name for one of [avilable regions](https://cloud.ibm.com/docs/Registry?topic=Registry-registry_overview#registry_regions).

To know more about IBM Cloud registry, see [Getting started with IBM Cloud Container Registry](https://cloud.ibm.com/docs/Registry?topic=Registry-getting-started).

Also see [Additional Build Parameters](additional-build-parameters.md).

## Deploying the Secure Build Server

Complete the following steps:  

1. Install the IBM Cloud CLI, and the HPVS plugin.
```buildoutcfg
curl -sL https://ibm.biz/idt-installer | bash
ibmcloud plugin install container-registry -r Bluemix -f
ibmcloud plugin install hpvs
```

2. Log in to IBM Cloud by using either an API key, or the Single Sign On (SSO) authentication. See [Getting started with the IBM Cloud CLI](https://cloud.ibm.com/docs/cli?topic=cli-getting-started) for more details.

3. Configure the `sbs-config.json` file with client certificates using one of the following options.
   1. Use build.py to create certificate-authority (CA) and client certificates which are used for secure communication from your client script to the SBS instance.
      ```buildoutcfg
      ./build.py create-client-cert --env <path>/sbs-config.json
      ```
      After you execute above command, a directory is generated that looks like this: `.SBContainer-9ab033ad-5da1-4c4e-8eae-ca8c468dbbcc.d`.
      You can notice that two parameters "UUID" and "SECRET", are added to the `sbs-config.json` file.
      UUID is used along with the container name where the generated certificates are stored.
      SECRET holds a randomly generated value, which needs to be preserved safely, used to deal with a state image of SBS. Continue to step #4.  
      Note:-      
      - Follow the best practices of certificate management.
      - The CA certificate should not be compromised or revoked.
      - Third-party certificates are not supported.
   2. Use your own certificate-authority (CA) and client certificates.
      1. Go to the CLI directory. If it is located at `~/git`, run the following command:
         ```
         cd ~/git/secure-build-cli
         ```
      2. Add the following path names to the  `sbs-config.json` file.
         Note that the `server-csr.pem` and `server-cert.pem` do not exist as yet. If the `./sbs-keys` directory doesn’t exist, you can create one by using the command `mkdir ./sbs-keys`.
         ```
         "CAPATH": "Path to CA certificate",
         "CAKEYPATH": "Path to CA key",
         "CLIENT_CRT_KEY": "Path to concatenated client cert and key",   //cat my-client-cert.pem my-client-cert-key.pem > my-client-cert-and-key.pem
         "CSRPATH": "./sbs-keys/server-csr.pem",
         "CERTPATH": "./sbs-keys/server-cert.pem",
         ```
         To get the base64-encoded certificates into CERT_ENV using build.py, run the following command:
         ```
         CERT_ENV=`./build.py instance-env --env <path>/sbs-config.json`
         ```
      3. Create a the Hyper Protect Virtual Servers instance by using the `ibmcloud hpvs instance-create` command.  
         ```
         ibmcloud hpvs instance-create docker.io-ibmzcontainers-acrux-dev1 lite-s syd05 --rd-path secure_build.asc --image-tag 1.3.0.1 $CERT_ENV
         ```
         Continue to step #6.            
         Note:-       
         - Follow the best practices of certificate management.
         - The CA certificate should not be compromised or revoked.
         - Third-party certificates are not supported.
4. Copy your CA and client certificates under directory `.SBContainer-9ab033ad-5da1-4c4e-8eae-ca8c468dbbcc.d` to file `client_base64` and `ca_base64` in a base64 format respectively.
```buildoutcfg
echo $(cat .SBContainer-9ab033ad-5da1-4c4e-8eae-ca8c468dbbcc.d/client-cert.pem | base64) | tr -d ' ' > client_base64
echo $(cat .SBContainer-9ab033ad-5da1-4c4e-8eae-ca8c468dbbcc.d/client-ca.pem | base64) | tr -d ' ' > ca_base64
```
Alternatively, you can get base64-encoded certificates by running the following command.
```buildoutcfg
./build.py instance-env --env <path>/sbs-config.json
```

5. Create the SBS instance on cloud.
```buildoutcfg
ca=$(cat ca_base64)
client=$(cat client_base64)
ibmcloud hpvs instance-create SBContainer lite-s dal13 --rd-path secure_build.asc -i 1.3.0.1 -e CLIENT_CRT=$client -e CLIENT_CA=$ca
```
Alternatively, you can copy & paste the output from `instance-env` command as command-line parameters for the `instance-create` command.
```buildoutcfg
ibmcloud hpvs instance-create SBContainer lite-s dal13 --rd-path secure_build.asc -i 1.3.0.1 -e CLIENT_CRT=... -e CLIENT_CA=...
```
Where:  
- SBContainer is the name of the SBS instance to be created.      
- lite-s is the plan name.  
- dal13 is the region name.  
- 1.3.0.1 is the image tag of Secure Docker Build docker image.

To know more details about which plan to use and which region to use, see [hpvs instance-create](https://cloud.ibm.com/docs/hpvs-cli-plugin?topic=hpvs-cli-plugin-hpvs_cli_plugin#create_instance).

6. You can list the Hyper Protect Virtual Servers instances.
```buildoutcfg
ibmcloud hpvs instances
```
After the instance is up and running, then you can see `Public IP address` in the instance list.

7. Copy this IP address in `sbs-config.json` as shown.
```buildoutcfg
"CICD_PUBLIC_IP": "<IP Address>"
```

## How to build image by using SBS
After you create the SBS instance, complete the following steps to build your image securely:  

1. Check the status of SBS.
```buildoutcfg
./build.py status --env <path>/sbs-config.json --noverify
```
Before initializing SBS, it returns an empty string as status.
```
INFO:__main__:status: response={
    "status": ""
}
```

2. Get a server certificate-signing-request (CSR) to sign with your CA.
```buildoutcfg
./build.py get-server-csr --env <path>/sbs-config.json --noverify
```
3. Sign the server CSR.
```buildoutcfg
./build.py sign-csr --env <path>/sbs-config.json
```
4. Post the signed server certificate to SBS.
```buildoutcfg
./build.py post-server-cert --env <path>/sbs-config.json --noverify
```
5. Now again check the status without `noverify` option.
```buildoutcfg
./build.py status --env <path>/sbs-config.json
```
The `post-server-cert` command lets SBS to install the signed certificate and
to restart the nginx server to make it effective.
From here, you don't need `--noverify`; the client verifies the server certificate
at every API call.
```
INFO:__main__:status: response={
    "status": "restarted nginx"
}
```
6. Initialize the configuration.
```buildoutcfg
./build.py init --env <path>/sbs-config.json
```
7. Build the image.
```buildoutcfg
./build.py build --env <path>/sbs-config.json
```
8. Check the build log.
```buildoutcfg
./build.py log --log build --env <path>/sbs-config.json
```
9. Check the status if the image has been built and pushed successfully.
```buildoutcfg
./build.py status --env <path>/sbs-config.json
```
As the build process makes a progress, the `status` response shows the last completed step.
Here is a typical sequence of responses for a successful build.
```
{
  ...
    "status": "cleaned up"
}
{
  ...
    "status": "github cloned"
}
{
  ...
    "status": "image built"
}
{
  ...
    "status": "image pushed"
}
{
  ...
    "status": "success"
}
```
When an error occurs, the `status` response shows the command that caused the error. Typically, you need to examine the build log
to fix the issue.
```
{
  ...
    "status": "exiting due to a non-zero return value: 1, cmd: docker build --disable-content-trust=false -t docker.io/abhiramk/nginxapp:latest -f Dockerfile ."
}
```
To stop a long-running build process, refer to [How to stop and clean up a build process](README.md#how-to-stop-and-clean-up-a-build-process).

## How to deploy the image that is built by using SBS
Complete the following steps:  

1. Get an encrypted registration definition file.
```buildoutcfg
./build.py get-config-json --env <path>/sbs-config.json --key-id <key_id> --email <your_email_as_id>
```
e.g. `--key-id isv_user --email isv@example.com`

The `<key_id>` is for a GPG key to sign the file. If omitted, the default id is `secure-build`. The email address
is used to identify the key. If omitted, the GPG library will pick up a default one, typically `<your_login_id>@<domain_name_of_client>`.

During above command you will be asked to create a passphrase. Enter the passphrase twice (the second time is for confirmation). Then again passphrase will be asked to sign the file.

Now the registration definition file for the newly built image, `sbs.enc`, is stored in your current directory. The file name is `REPO_ID` in sbs-config.json + `.enc`.


2. Get the build image tag, which is `IMAGE_TAG_PREFIX` in sbs-config.json + `<suffix>`, by using one of the following options:

a. Run the following command to see the image tag after building the image.
```buildoutcfg
# ./build.py status --env <path>/sbs-config.json
INFO:__main__:status: response={
 ..........
    "image_tag": "s390x-v0.3-60fd72e",
..........
}
```
Use this `image_tag`.

b. You can log in to your container registry (e.g. Docker Hub) and check the tag.

3. Create the Hyper Protect Virtual Servers instance by using the `ibmcloud hpvs instance-create` command.
```buildoutcfg
ibmcloud hpvs instance-create container_name lite-s dal13 --rd-path sbs.enc -i image_tag {-e listed_environment_variable1=value1 ...}
```

## Manifest file
The SBS instance creates a manifest file at each successful build as a snapshot of build materials for audit purposes. The developer can verify the integrity of the built image and the artifacts used for building the image. Using this Manifest file is optional.

## How to store Manifest file in IBM Cloud Object Storage

1. Add the following parameters to your `sbs-config.json` file.
```buildoutcfg
    "COS_API_KEY_ID": "<your_cloud_apikey>",
    "COS_RESOURCE_CRN": "<your_cloud_resource_crn_id>",
    "COS_ENDPOINT": "<your_public_cos_endpoint>",
    "COS_AUTH_ENDPOINT": "https://iam.cloud.ibm.com/oidc/token",
    "MANIFEST_BUCKET_NAME": "<your_bucket_name>",
```
`COS_ENDPOINT` specifies the public endpoint of your COS instance (e.g. https://s3.us-east.cloud-object-storage.appdomain.cloud). Don't forget the leading `https://`.
You need to create the bucket specified by `MANIFEST_BUCKET_NAME` if it doesn't exist.

2. Update the SBS instance with the new COS parameters.
```buildoutcfg
./build.py update --env <path>/sbs-config.json
```

3. Build the image.
```buildoutcfg
./build.py build --env <path>/sbs-config.json
```

This will store your manifest file to IBM Cloud Object Storage.


## How to get the Manifest file

1. Get the latest manifest file directly from SBS.
```buildoutcfg
./build.py get-manifest --env <path>/sbs-config.json
```

This will store your manifest file to current working directory, something similar to `manifest.docker.io.abhiramk.nginxapp.v1-d14cdc8.2021-02-04_13-25-52.512466.sig.tbz`.

2. Verifying the integrity of the Manifest file
```buildoutcfg
./build.py get-manifest --env <path>/sbs-config.json  --verify-manifest
```

## How to extract build materials from the Manifest file

Untar by using the `tar` command.
```buildoutcfg
tar -xvf manifest.docker.io.abhiramk.nginxapp.v1-d14cdc8.2021-02-04_13-25-52.512466.sig.tbz
manifest.docker.io.abhiramk.nginxapp.v1-d14cdc8.2021-02-04_13-25-52.512466.tbz
manifest.docker.io.abhiramk.nginxapp.v1-d14cdc8.2021-02-04_13-25-52.512466.sig
```

Further untar to get the build materials.
```buildoutcfg
tar -xvf manifest.docker.io.abhiramk.nginxapp.v1-d14cdc8.2021-02-04_13-25-52.512466.tbz
```

You will see a data and git folder.
- The data directory provides the `build.json` and `build.log` files which contain the build status and the build log, respectively.
- The git directory contains the snapshot of the cloned git repository of the source code on the SBS instance when the build was completed.


## State image
The state image contains the private signing key, which is generated when a built image is pushed to a container registry for the first time. It is encrypted by using two SECRETS. One is generated by `build.py` and stored in your `sbs-config.json`. The other one is included in the SBS image.

Why do we need the state image?
You need it to recover the signing key and additional SBS internal states to build the image in a new SBS instance after the original instance is deleted or corrupted.

## How to get the state image
1. Get the state image locally.
```buildoutcfg
./build.py get-state-image --env <path>/sbs-config.json
```
There will be an encrypted file which will be downloaded in your current directory, similar to this:
```buildoutcfg
docker.io.prabhat54331.sbs22.s390x-v0.1-60fd72e.2020-10-21_07-20-08.516797
```

2. You can also save the state image to IBM Cloud Object Storage (COS).

    1) You first create a bucket on IBM Cloud Object Storage.

    2) Add below parameters into `sbs-config.json`.

      ```buildoutcfg
      "COS_API_KEY_ID": "<your_cloud_apikey>",
      "COS_RESOURCE_CRN": "<your_cloud_resource_crn_id>",
      "COS_ENDPOINT": "<your_public_cos_endpoint>",
      "COS_AUTH_ENDPOINT": "https://iam.cloud.ibm.com/oidc/token",
      "STATE_BUCKET_NAME": "<your_bucket_name>",
      ```

      If you already have COS parameters for the manifest in `sbs-config.json`, add `STATE_BUCKET_NAME` only.

    3) Update the configuration.

      ```buildoutcfg
      ./build.py update --env <path>/sbs-config.json
      ```

    4) Save the state image to COS.

      ```buildoutcfg
      ./build.py get-state-image --env <path>/sbs-config.json {--state-bucket-name <your_bucket_name>}
      ```

      Use the `--state-bucket-name` option, if you want to override the parameter in `sbs-config.json` or you don't have one in the file.
      When you save the state image to COS, you still get meta data of the state image in a local file of the same name as the state image file.

## How to recover the state image
Complete the following steps:   

1. Create a new SBS instance as mentioned in the section [Deploying the Secure Build Server](README.md#deploying-the-secure-build-server), with the same secret that was used to get the state image, otherwise the post state image operation fails.

2. Check the status of SBS.
```buildoutcfg
./build.py status --env <path>/sbs-config.json --noverify
```
3. Get a server CSR to sign with your CA
```buildoutcfg
./build.py get-server-csr --env <path>/sbs-config.json --noverify
```
4. Sign the server CSR.
```buildoutcfg
./build.py sign-csr --env <path>/sbs-config.json
```
5. Post the signed server certificate to SBS.
```buildoutcfg
./build.py post-server-cert --env <path>/sbs-config.json --noverify
```
6. Now again check the status.
```buildoutcfg
./build.py status --env <path>/sbs-config.json
```
7. Post the state image.
```buildoutcfg
./build.py post-state-image --state-image docker.io.prabhat54331.sbs22.s390x-v0.1-60fd72e.2020-10-21_07-20-08.516797 --env <path>/sbs-config.json
```
Use the `--state-image` option to specify the state image file you downloaded previously with the `get-state-image` command.

8. Update the configuration.
```buildoutcfg
./build.py update --env <path>/sbs-config.json
```
9. Now you can further build your image using build command. Eventually your Docker image will be pushed to same registry.
```buildoutcfg
./build.py build --env <path>/sbs-config.json
```
10. Check the build log and wait until the build operation is completed
```buildoutcfg
./build.py log --log build --env <path>/sbs-config.json
```
11. Check the status of the container
```buildoutcfg
./build.py status --env <path>/sbs-config.json
```

## How to recover state image from Cloud Object Storage
Complete the following steps:  

1. Create a new SBS server as mentioned in the section [Deploying the Secure Build Server](README.md#deploying-the-secure-build-server), and use the same secret that was used to get the state image, otherwise the post state image operation fails.

2. Check the status of SBS.
```buildoutcfg
./build.py status --env <path>/sbs-config.json --noverify
```

3. Get a server CSR to sign with your CA.
```buildoutcfg
./build.py get-server-csr --env <path>/sbs-config.json --noverify
```

4. Sign the server CSR.
```buildoutcfg
./build.py sign-csr --env <path>/sbs-config.json
```

5. Post the signed server certificate to SBS.
```buildoutcfg
./build.py post-server-cert --env <path>/sbs-config.json --noverify
```

6. Now again check the status.
```buildoutcfg
./build.py status --env <path>/sbs-config.json
```

7. Use the same `sbs-config.json` file. Ensure that you have changed the parameter `CICD_PUBLIC_IP` with the newly created IP address of your SBS server.

8. Initialize the configuration.
```buildoutcfg
./build.py init --env <path>/sbs-config.json
```

9. Post the state image.
```buildoutcfg
./build.py post-state-image --env <path>/sbs-config.json --name docker.io.prabhat54331.sbs22.s390x-v0.1-60fd72e.2020-10-21_07-20-08.516797 {--state-bucket-name <your_bucket_name>}
```
Use the `--state-bucket-name` option, if you want to override the parameter in `sbs-config.json` or you don't have one in the file.
Use the `--name` option to specifiy the name of the state image on COS, which is the same as the name of the meta data file you downloaded with the `get-state-image` command.

10. Update the configuration.
```buildoutcfg
./build.py update --env <path>/sbs-config.json
```
11. You can build your image using build command. Eventually your Docker image will be pushed to same registry.
```buildoutcfg
./build.py build --env <path>/sbs-config.json
```
12. Check the build log and wait until the build operation is completed.
```buildoutcfg
./build.py log --log build --env <path>/sbs-config.json
```
13. Check the status of SBS.
```buildoutcfg
./build.py status --env <path>/sbs-config.json
```

## How to stop and clean up a build process
SBS can take one build task at a time. If you want to start another build before an on-going
build completes successfully or prematurely with an error, you need to stop and clean up
the on-going build first.

1. You can always check the status of SBS using the `status` command.
```buildoutcfg
./build.py status --env <path>/sbs-config.json
```

2. Clean up SBS if you want to run another build without waiting for an on-going build to complete.
```buildoutcfg
./build.py clean --env <path>/sbs-config.json
```

3. Check the status again.
```buildoutcfg
./build.py status --env <path>/sbs-config.json
```
After the `clean` command completes successfully, the `status` command should return `restarted cicd`. This indicates the build service (cicd)
has been restarted and is ready to accept a new `build` command.
```
{
...
    "status": "restarted cicd"
}
```

## How to change the SECRET to a randomly generated NEW_SECRET
Complete the following steps:  

1. You can always update the secret to a new one in the `sbs-config.json` file. To update the secret, run the following command.
```buildoutcfg
./build.py update --env <path>/sbs-config.json --new-secret
```
`SECRET` will be updated with a randomly generated base64 value in the `sbs-config.json` file if the update operation is successful.

Note: After the secret is updated, you cannot use a state image obtained using the previous one. Consider obtaining a state image again with the new secret.

## License

[Apache 2.0](https://github.com/ibm-hyper-protect/secure-build-cli/blob/main/LICENSE)

## Contributor License Agreement (CLA)

To contribute to the secure-build-cli project, it is required to sign the
[individual CLA form](https://gist.github.com/moriohara/6ecc6cca48f4c018160e35ebd4e0eb8a)
if you're contributing as an individual, or
[corporate CLA form](https://gist.github.com/moriohara/e2ad4706f1142089c181d1583f8e6883)
if you're contributing as part of your job.

You are required to do this only once at on-line with [cla-assistant](https://github.com/cla-assistant/cla-assistant) when a pull request is created, and then you are free to contribute to the secure-build-cli project.
