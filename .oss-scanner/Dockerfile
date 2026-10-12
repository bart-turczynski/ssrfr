# Build for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner).
# The scanner builds this with the repository as the context, then audits the
# image with no network, so everything the tests need is installed here.
# ssrfr is pure R: no compiler flags to set. Its tests serve on loopback only
# (webfakes, httpuv, `openssl s_server`) and mock the resolver, so they run
# with no network; the two advisory-feed tests skip offline.
FROM rocker/r-ver:4.6.1

# The openssl command-line tool, for the SNI test in test-fetch-tls.R.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Imports and Suggests, with the system libraries they need.
RUN Rscript -e 'install.packages("pak")' \
 && Rscript -e 'pak::local_install_deps("/src", dependencies = TRUE, upgrade = FALSE)'

RUN R CMD INSTALL /src

# Smoke-test the image; failures are logged, not fatal.
RUN Rscript -e 'testthat::test_local("/src", stop_on_failure = TRUE)' \
 || echo "WARNING: tests reported failures"
