# IBM Cloud Hyper Protect Virtual Servers Secure Build Server

IBM Cloud Hyper Protect Virtual Servers Secure Build Server, also referred to as Secure Build Server (SBS) allows you to build a trusted container image within a secure enclave, provided by [IBM Cloud Hyper Protect Virtual Servers](https://cloud.ibm.com/catalog/services/hyper-protect-virtual-server). The enclave is highly isolated - developers can access the container only by using a specific API and the cloud administrator cannot access the contents of the container as well, thereby the created image can be highly trusted. Specifically, the build server cryptographically signs the image, and a manifest (which is a collection of materials used during the build for audit purposes). Since the enclave protects signing keys inside the enclave, the signatures can be used to verify whether the image and manifest are from the build server, and not somewhere else.

The following diagram illustrates a high level structure of SBS, which is provisioned by an administrator by using the [ibmcloud CLI](https://cloud.ibm.com/docs/cli?topic=hpvs-cli-plugin-hpvs_cli_plugin). This document describes how a developer can interact with the server by using the `build.py` script. A developer prepares the source code of an application with Dockerfile, in a source code repository such as GitHub. The build server pulls the source code, builds a container image by using the Dockerfile, signs it, and pushes it to a container registry, such as Docker Hub. During the build process, it also creates a manifest file and signs it. Optionally, it can
push the manifest to Cloud Object Storage, or the developer can download it on a local file system. The build server can also export and import its state as a single file, which includes signing keys of the image and manifest, with build parameters. When exported, the state is encrypted in such a way that the developer or IBM cannot decrypt the state image outside the enclave. It can be decrypted only inside the enclave. The encrypted state image can be pushed to Cloud Object Storage, or the developer can download it on a local file system.

<p align="center">
  <img src="./images/secure-build.png">
</p>

<!--
Secure Build Service is basically used to build and sign docker images where signing key will be secure. No one can see signing private key. Even image builder can not see the signing private key.
-->

## Before you begin

The following is a list of hardware or software requirements:
- Linux management server from where you can run the build CLI tool(Linux workstation).
  - x86 architecture  
  - Ubuntu 18.04 or 16.04 (64 bit)
  - Python 3.6 (Python 2.x is not supported)
- Access to GitHub for hosting the source code.
- Dockerfile (everything that you need to build your container image).
- Access to IBM Cloud Registry or DockerHub.
- (Optional) Access to IBM Cloud Object Storage (COS) Service.
- Access to IBM Hyper Protect Virtual Servers.


## Install the CLI
The CLI script is written in Python and has been tested using Python 3.6.9. You must install Python 3.0 and pip3, if you don't have them on your client system. The build.py is the main script that comes with secure-build-cli. This script helps you to interact and do the required operations on the SBS virtual server after it is created by using the IBM Cloud CLI. For systems that run Ubuntu, you can run the following commands to install them.
```
apt-get update
apt-get install python3 python3-pip
```

After you run the commands listed above, clone the repository, and install the dependencies by running the following commands:

```
git clone git@github.com:ibm-hyper-protect/secure-build-cli.git
cd secure-build-cli
pip3 install -r requirements.txt
```

## Preparing the configuration
Create the `sbs-config.json` file and add the following content in the file:
```
{
  "CICD_PUBLIC_IP": "",
  "CICD_PORT": "443",
  "IMAGE_TAG": "1.3.0",
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
    "<BUILD_ARG1>": "<VALUE1>"
    "<BUILD_ARG2>": "<VALUE2>"
  }
}
```

Where
```
CICD_PUBLIC_IP - IP address of the SBS server. Leave it as "" since it is unknown until the server is provisioned.
CICD_PORT - port on which the SBS server is running.
IMAGE_TAG - image tag of the container image to be deployed as SBS server. Use "1.3.0" unless otherwise noted.
GITHUB_KEY_FILE - Private key path of your GitHub.
GITHUB_URL - GitHub URL.
GITHUB_BRANCH - GitHub branch name.
CONTAINER_NAME - Name of the Hyper Protect Virtual Server which you want to create on cloud. This name can be different than the name which you use on cloud.
REPO_ID - This is the ID which is internally used once you will build image. You can chose any name.
DOCKER_REPO - DockerHub repository.
DOCKER_USER - docker user name who has write access to above repository.
DOCKER_PASSWORD - docker password who has write access to above repository.
IMAGE_TAG_PREFIX - a prefix of the image tag for the image to be built. The full image tag will be IMAGE_TAG_PREFIX + '-' + the leading seven digits from the GitHub repository hash.
DOCKER_CONTENT_TRUST_BASE - If your base image that is mentioned in the Dockerfile is signed, then make it true.
DOCKER_CONTENT_TRUST_BASE_SERVER - If your base image mentioned in the Dockerfile is signed, then use the notory URL - https://notary.docker.io.
DOCKER_RO_USER - you can use the same as DOCKER_USER. It is recommended that you specify a user who has read access only to your Docker repository.
DOCKER_RO_PASSWORD - you can use same as DOCKER_PASSWORD. It is recommended that you specify a user who has read access only to your Docker repository.
ENV_WHITELIST - All environment variable names need to be listed. The Hyper Protect environment does not allow any environment variable unless it is in this list because of security reason.
ARG - You have to pass all build argument parameter as you pass during Docker build.
```

Note: - If you use IBM Cloud Registry instead of DockerHub registry, then you must use the following parameters:

```buildoutcfg
"DOCKER_BASE_SERVER": "us.icr.io",
"DOCKER_PUSH_SERVER": "us.icr.io",
"DOCKER_USER": "iamapikey",
"DOCKER_PASSWORD": "<ibm cloud apikey>"
"DOCKER_RO_USER": "iamapikey",
"DOCKER_RO_PASSWORD": "<ibm cloud apikey>",
"DOCKER_CONTENT_TRUST_PUSH_SERVER": "https://us.icr.io:4443",
```
The location can be other than `us`. To know more about IBM Cloud registry, see [Getting started with IBM Cloud Container Registry](https://cloud.ibm.com/docs/Registry?topic=Registry-getting-started).


## Deploying the Secure Build Server

Complete the following steps:  

1. Install the IBM Cloud CLI, and the HPVS plugin.
```buildoutcfg
curl -sL https://ibm.biz/idt-installer | bash
ibmcloud plugin install container-registry -r Bluemix -f
ibmcloud plugin install hpvs
```

2. Log in to IBM cloud by using either the Single Sign On (SSO) authentication, or by using the API key. See [Getting started with the IBM Cloud CLI](https://cloud.ibm.com/docs/cli?topic=cli-getting-started) for more details.

3. Create ca and client certificate which is used for secure communication from your client script to the SBS container.
```buildoutcfg
# ./build.py create-client-cert --env sbs-config.json
```
After you execute above command, a directory is generated that looks like this: `.SBContainer-9ab033ad-5da1-4c4e-8eae-ca8c468dbbcc.d`.
You can notice that two parameters "UUID" and "SECRET", are added to the `sbs-config.json` file.
UUID is used along with the container name where the generated certificates are stored.
SECRET holds a randomly generated value, which needs to be preserved safely which is used during the get state image, and recover state image of SBS.

4. Copy your client certificate and ca certificate in base64 format which will be under directory `.SBContainer-9ab033ad-5da1-4c4e-8eae-ca8c468dbbcc.d` and save in file `client_base64` and `ca_base64` respectively.
```buildoutcfg
# echo $(cat .SBContainer-9ab033ad-5da1-4c4e-8eae-ca8c468dbbcc.d/client-cert.pem | base64) | tr -d ' ' > client_base64
# echo $(cat .SBContainer-9ab033ad-5da1-4c4e-8eae-ca8c468dbbcc.d/client-ca.pem | base64) | tr -d ' ' > ca_base64
```
Alternatively, you can get base64-encoded certificates by running the following command.
```buildoutcfg
# ./build.py instance-env --env sbs-config.json
```

5. Create the SBS instance on cloud.
```buildoutcfg
# ca=$(cat ca_base64)
# client=$(cat client_base64)
# ibmcloud hpvs instance-create SBContainer lite-s dal13 --rd-path "secure_build.asc" -i 1.3.0 -e CLIENT_CRT=$client -e CLIENT_CA=$ca
```
Alternatively, you can copy & paste the output from `instance-env` command as command-line parameters for the `instance-create` command.
```buildoutcfg
# ibmcloud hpvs instance-create SBContainer lite-s dal13 --rd-path "secure_build.asc" -i 1.3.0 -e CLIENT_CRT=... -e CLIENT_CA=...
```
Where:  
- SBContainer is the name of the SBS instance to be created.      
- lite-s is the plan name.  
- dal13 is the region name.  
- 1.3.0 is the image tag of Secure Docker Build docker image.  
To know more details about which plan to use and which region to use, see [hpvs instance-create](https://cloud.ibm.com/docs/hpvs-cli-plugin?topic=hpvs-cli-plugin-hpvs_cli_plugin#create_instance).

6. You can list the hyper protect instances.
```buildoutcfg
# ibmcloud hpvs instances
```
After SBS is up and running, then you can see `Public IP address  ` after listing the instances.

7. Copy this IP address in `sbs-config.json` as shown.
```buildoutcfg
"CICD_PUBLIC_IP": "<IP Address>"
```

## How to build image by using Secure Build Server
After you create the SBS virtual server, complete the following steps to build your image securely:  

1. Check the status of SBS.
```buildoutcfg
# ./build.py status --env sbs-config.json --noverify
```
2. Get server csr to sign with ca.
```buildoutcfg
# ./build.py get-server-csr --env sbs-config.json --noverify
```
3. Sign server csr.
```buildoutcfg
# ./build.py sign-csr --env sbs-config.json
```
4. Post signed server certificate to SBS.
```buildoutcfg
# ./build.py post-server-cert --env sbs-config.json --noverify
```
5. Now again check status without no-verify.
```buildoutcfg
# ./build.py status --env sbs-config.json
```
6. Initialise configuration.
```buildoutcfg
# ./build.py init --env sbs-config.json
```
7. Build image.
```buildoutcfg
# ./build.py build --env sbs-config.json
```
8. Check build log.
```buildoutcfg
# ./build.py log --log build --env sbs-config.json
```
9. Check status if the image has been built and pushed successfully.
```buildoutcfg
# ./build.py status --env sbs-config.json
```


## How to deploy the image that is built by using SBS
Complete the following steps:  

1. Get the Encrypted repository json file.
```buildoutcfg
# ./build.py get-config-json --env sbs-config.json --key-id <key-id> --email <your-email-as-id>
```
eg `--key-id isv_user --email isv@example.com`

The <key-id> is for a GPG key to sign the file. If omitted, the default id is `secure-build`. The email address
is used to identify the key. If omitted, the GPG library will pick up a default one, typically <your-login-id>@<domain-name-of-client>.

During above command you will be asked to create a passphrase. Enter the passphrase twice (the second time is for confirmation). Then again passphrase will be asked to sign the file.

Now `sbs.enc` file will be stored in your current directory.


2. Get the build image tag. `Build image tag = IMAGE_TAG_PREFIX + suffix` by using one of the following options:

a. Run following command to see image tag after building the image.
```buildoutcfg
# ./build.py status --env sbs-config.json
INFO:__main__:status: response={
 ..........
    "image_tag": "s390x-v0.3-60fd72e",
..........
}
```
Use this `image_tag`.

b. You can log in to your container registry (e.g. Docker Hub) and check the tag.

3. Create the Hyper Protect Virtual Server instance by using the `ibmcloud hpvs` CLI commands.
```buildoutcfg
#ibmcloud hpvs instance-create container_name lite-s dal13 --rd-path "sbs.enc" -i image_tag
```

## Manifest file
The Secure Build creates a manifest file at each successful build as a snapshot of build materials for audit purposes. The developer can verify the integrity of the built image and the artifacts used for building the image.

## How to store Manifest file in IBM Cloud Object storage

1. Add the following parameters to your `sbs-config.json` file.
```buildoutcfg
    "COS_API_KEY_ID": "<your_cloud_apikey>",
    "COS_RESOURCE_CRN": "<your_cloud_resource_crn_id",
    "COS_ENDPOINT": "https://s3.jp-tok.cloud-object-storage.appdomain.cloud",
    "COS_AUTH_ENDPOINT": "https://iam.cloud.ibm.com/oidc/token",
    "MANIFEST_BUCKET_NAME": "bucketName",
```
2. Update the SBS server with the new COS parameters.
```buildoutcfg
# ./build.py update --env sbs-config.json
```

3. Build image.
```buildoutcfg
# ./build.py build --env sbs-config.json
```

This will store your manifest file to IBM Cloud Object Storage.


## How to get the Manifest file

1. Add the following parameters to your `sbs-config.json` file.
```buildoutcfg
# ./build.py get-manifest --env sbs-config.json
```

This will store your manifest file to current working directory, something similar to `manifest.docker.io.abhiramk.nginxapp.v1-d14cdc8.2021-02-04_13-25-52.512466.sig.tbz`.

2. Verifying the integrity of the Manifest file
```buildoutcfg
# ./build.py get-manifest --env sbs-config.json  --verify-manifest
```

## How to extract Manifest files

Untar by using the `tar` command.
```buildoutcfg
# tar -xvf manifest.docker.io.abhiramk.nginxapp.v1-d14cdc8.2021-02-04_13-25-52.512466.sig.tbz
manifest.docker.io.abhiramk.nginxapp.v1-d14cdc8.2021-02-04_13-25-52.512466.tbz
manifest.docker.io.abhiramk.nginxapp.v1-d14cdc8.2021-02-04_13-25-52.512466.sig
```

Further untar to get the build Materials.
```buildoutcfg
# tar -xvf manifest.docker.io.abhiramk.nginxapp.v1-d14cdc8.2021-02-04_13-25-52.512466.tbz
```

You will see a data and git folder.
- The data directory provides the `build.json` and `build.log` files which contains the build status and the build log, respectively.
- The git directory contains the snapshot of the cloned git repository of the source code on the Secure Build instance when the build was completed.


## State image
The state image contains the private signing key, which is generated when a built image is pushed to a container registry for the first time. It is encrypted by using two SECRETS. One is generated by `build.py` and stored in your `sbs-config.json`. The other one is included in the SBS image.

Why do we need the state image?
You need it to recover the signing key and additional SBS internal states to build the image in a new SBS server instance after the original instance is deleted or corrupted.

## How to get state image
1. Get the state image locally.
```buildoutcfg
# ./build.py get-state-image --env sbs-config.json
```
There will be an encrypted file which will be downloaded in your current directory, similar to this:
```buildoutcfg
docker.io.prabhat54331.sbs22.s390x-v0.1-60fd72e.2020-10-21_07-20-08.516797
```

2. You can also save state image to Cloud Object Storage (COS).

 1. You first create bucket on IBM cloud object storage.

 2. Add below parameter into `sbs-config.json`.
    ```buildoutcfg
        "COS_API_KEY_ID": "<your_cloud_apikey>",
        "COS_RESOURCE_CRN": "<your_cloud_resource_crn_id",
        "COS_ENDPOINT": "https://s3.jp-tok.cloud-object-storage.appdomain.cloud",
        "COS_AUTH_ENDPOINT": "https://iam.cloud.ibm.com/oidc/token",
        "STATE_BUCKET_NAME": "bucketName",
    ```
    If you already have COS parameters for the manifest in `sbs-config.json`, add `STATE_BUCKET_NAME` only.

 3. Update config.
    ```buildoutcfg
    # ./build.py update --env sbs-config.json
    ```

 4. Save the state image to COS.
    ```buildoutcfg
    # ./build.py get-state-image --env sbs-config.json {--state-bucket-name bucketName}
    ```
    Use the `--state-bucket-name` option, if you want to override the parameter in `sbs-config.json` or you don't have one in the file.

## How to recover the state image
Complete the following steps:   

1. Create a new SBS server as mentioned in the section [Deploying the Secure Build Server](README.md#deploying-the-secure-build-server),  and use the same secret that was used to get the state image, otherwise the post state image operation fails.

2. Check the status of SBS.
```buildoutcfg
# ./build.py status --env sbs-config.json --noverify
```
3. Get server csr to sign with ca.
```buildoutcfg
# ./build.py get-server-csr --env sbs-config.json --noverify
```
4. Sign server csr.
```buildoutcfg
# ./build.py sign-csr --env sbs-config.json
```
5. Post signed server certificate to SBS.
```buildoutcfg
# ./build.py post-server-cert --env sbs-config.json --noverify
```
6. Now again check the status.
```buildoutcfg
# ./build.py status --env sbs-config.json
```
7. Post the state image.
```buildoutcfg
# ./build.py post-state-image --state-image docker.io.prabhat54331.sbs22.s390x-v0.1-60fd72e.2020-10-21_07-20-08.516797 --env sbs-config.json
```
8. Update the configuration.
```buildoutcfg
# ./build.py update --env sbs-config.json
```
9. Now you can further build your image using build command. Eventually your Docker image will be pushed to same registry.
```buildoutcfg
# ./build.py build --env sbs-config.json
```
10. Check the build log and wait until the build operation is completed
```buildoutcfg
# ./build.py log --log build --env sbs-config.json
```
11. Check the status of the container
```buildoutcfg
# ./build.py status --env sbs-config.json
```

## How to recover state image from Cloud object
Complete the following steps:  

1. Create a new SBS server as mentioned in the section [Deploying the Secure Build Server](README.md#deploying-the-secure-build-server), and use the same secret that was used to get the state image, otherwise the post state image operation fails.

2. Check the status of SBS.
```buildoutcfg
# ./build.py status --env sbs-config.json --noverify
```

3. Get server csr to sign with ca.
```buildoutcfg
# ./build.py get-server-csr --env sbs-config.json --noverify
```

4. Sign server csr.
```buildoutcfg
# ./build.py sign-csr --env sbs-config.json
```

5. Post signed server certificate to SBS.
```buildoutcfg
# ./build.py post-server-cert --env sbs-config.json --noverify
```
6. Now again check status.
```buildoutcfg
# ./build.py status --env sbs-config.json
```

7. Use the same `sbs-config.json` file. Ensure that you have changed the parameter `CICD_PUBLIC_IP` with the newly created IP address of your SBS server.

8. Initialize the configuration.
```buildoutcfg
# ./build.py init --env sbs-config.json
```

9. Post the state image.
```buildoutcfg
# ./build.py post-state-image --env sbs-config.json --name docker.io.prabhat54331.sbs22.s390x-v0.1-60fd72e.2020-10-21_07-20-08.516797 --bucket-name bucketName
```

10. Now you can further build your image using build command. Eventually your Docker image will be pushed to same registry.
```buildoutcfg
# ./build.py build --env sbs-config.json
```

11. Check the build log and wait until the build operation is completed
```buildoutcfg
# ./build.py log --log build --env sbs-config.json
```

12. Check the status of the container
```buildoutcfg
# ./build.py status --env sbs-config.json
```

## How to change the SECRET to a randomly generated NEW_SECRET
Complete the following steps:  

1. You can always update the secret to a new one in the `sbs-config.json` file. To update the secret, run the following command.
```buildoutcfg
# ./build.py update --env sbs-config.json --new-secret
```
`SECRET` will be updated with randomly generated base64 value in the `sbs-config.json` file if the update operation is successful.

Note: After the secret is updated, you cannot use a state image obtained using the previous one. Consider obtaining a state image again with the new secret.

## License

[Apache 2.0](https://github.com/ibm-hyper-protect/secure-build-cli/blob/main/LICENSE)

## Contributor License Agreement (CLA)

To contribute to the secure-build-cli project, it is required to sign the
[individual CLA form](https://gist.github.com/moriohara/6ecc6cca48f4c018160e35ebd4e0eb8a)
if you're contributing as an individual, or
[corporate CLA form](https://gist.github.com/moriohara/e2ad4706f1142089c181d1583f8e6883)
if you're contributing as part of your job.

You are only required to do this once at on-line with [cla-assistant](https://github.com/cla-assistant/cla-assistant) when a pull request is created, and then you are free to contribute to the secure-build-cli project.
