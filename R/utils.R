# General helpers with no home in one guard layer.

# `x`, or `default` when `x` is NULL. Base R has no such operator below 4.4.0.
default_if_null <- function(x, default) if (is.null(x)) default else x
