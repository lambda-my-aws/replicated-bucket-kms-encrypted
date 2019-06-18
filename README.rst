encrypted-replicated-bucket
=======

This simple template aims to allow to create s3 bucket replication very simply across 2 Regions with the least parameters unrelated to S3 settings.


Requirements
-----

You will need to have created the CFN Macro `cfnmacro-kmskey` which you can install in about 2 minutes from `here <https://github.com/ews-network/cfnmacro-kmskey>`_



To come
----

Once I will have updated Ozone to make use of the Organization class properly, and a few more AWS macros, it will also allow to use the template for CloudTrail with specific KMS policies and Bucket policy for the source region.
