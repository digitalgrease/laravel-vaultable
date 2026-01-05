# Digital Grease Laravel Vaultable

* Install the package
* Run migraton to add Vault Headers table
* Config allows to define the time limit a VMK is unlocked for after providing the password
* Config allows to define a "pepper" value
* Config allows to define an array of models observed (User is default)
* Config allows to define the "password/key" field of the model used to create the KEK for encrypting the VMK
* Register observer/listener to create vault header for models when:
  * model is created
  * model logs in and does not have one already
* Register observer/listener to re-encrypt VMK when password changed
* Register observer/listener to decrypt and add the VMK to an encrypted session/cookie on login event
* Register observer/listener to invalidate/remove the VMK from encrypted session/cookie on logout event
* Register a middleware to check if VMK is still unlocked

---

* Next steps - encrypting/decrypting data at rest - start with passwords and notes to replace LastPass
