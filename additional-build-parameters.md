# Additional Build Parameters

## DOCKERFILE_PATH and DOCKER_BUILD_PATH

`DOCKERFILE_PATH` defines the path name of the Dockerfile to be used during a build, and
`DOCKER_BUILD_PATH` defines the build directory. Both are relative to the top of the repo directory. 

Here, we show how these two parameters work using an example. Supposed we have a `project_repo` repository on GitHub, 
where we have `Dockerfile` and `dirname` at the top directory and a `work` subdirectory, as shown below.
```
$ cd project_repo
$ cat Dockerfile
FROM nginx
ADD dirname .
RUN DIR=`cat dirname` && echo "<html><body><p>build dir at ${DIR}, and Dockerfile at top.</p></body></html>" > /usr/share/nginx/html/index.html

$ cat dirname
top

$ cd work
$ cat Dockerfie
FROM nginx
ADD dirname .
RUN DIR=`cat dirname` && echo "<html><body><p>build dir at ${DIR}, and Dockerfile at work.</p></body></html>" > /usr/share/nginx/html/index.html

$ cat dirname
work
```

Both Dockerfiles create a nginx Web server container with a modified default page.
By accessing the page, we can find which Dockerfile and build directory were used during a build.

The following table shows four combinations of `DOCKERFILE_PATH` and `DOCKER_BUILD_PATH` values. As you can see,
`DOCKERFILE_PATH` is always relative to the top of the repo directory even when the build directory
is a subdirectory.

| DOCKERFILE_PATH   | DOCKER_BUILD_PATH | Text to be shown at nginx default page    |
|-------------------|-------------------|-------------------------------------------|
| "Dockerfile"      | ""                | build dir at top, and Dockerfile at top.  |
| "Dockerfile"      | "work"            | build dir at work, and Dockerfile at top. |
| "work/Dockerfile" | ""                | build dir at top, and Dockerfile at work. |
| "work/Dockerfile" | "work"            | build dir at work, and Dockerfile at work.|

Using these two parameters, you can build multiple kinds of container images out of a single GitHub repo. If you want to use a single SBS instance
to build those images and to push them to the same container repository, please note the following behavior of SBS.

- Use a different `IMAGE_TAG_PREFIX` for a different container built from the same GitHub repo. Otherwise, the same image tag will be assigned to multiple containers, and hence only the image pushed last remains accessible.
- Make sure to run `./build.py update` to update build parameters (e.g. `DOCKERFILE_PATH`, `DOCKER_BUILD_PATH`, `IMAGE_TAG_PREFIX`) inside the SBS instance to build a different container. Your modifications to a config json file won't be effective until you run `./build.py update`.
