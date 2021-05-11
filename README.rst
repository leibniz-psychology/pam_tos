PAM Terms of Service Module
===========================

PAM session module that verifies terms of service have been accepted before
allowing system access. The terms are fetched from an LDAP server and a user
attribute is written to, allowing integration with existing user databases.

Usage
-----

.. code::

	make
	make install

Then add

.. code::

	account required pam_tos.so config=/etc/pam-tos.conf

to your PAM configuration and edit ``/etc/pam-tos.conf`` accordingly. Make sure
the config file is not world-readable.

You also want to import the schema ``pam-tos.schema`` into your LDAP server and
add actual terms of use entries for example using

.. code:: console

	ldapadd -Y EXTERNAL -H ldapi:/// <<EOF
	dn: ou=terms,dc=example,dc=org
	ou: terms
	objectClass: top
	objectClass: organizationalUnit

	dn: x-termsId=tosde,ou=terms,dc=example,dc=org
	objectClass: top
	objectClass: x-termsAndConditions
	x-termsId: tosde
	x-termsKind: tos
	x-termsLanguage: de
	x-termsContent:< file:///path/to/tos.md
	EOF

Only users in the ``x-signatory`` object class are prompted to accept. Everyone
else is allowed access unconditionally.

