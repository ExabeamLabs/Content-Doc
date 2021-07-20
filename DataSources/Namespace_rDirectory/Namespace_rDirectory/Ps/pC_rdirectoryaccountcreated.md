#### Parser Content
```Java
{
Name = rdirectory-account-created
  Vendor = Namespace rDirectory
  Product = Namespace rDirectory
  Lms = Direct
  DataType = "account-creation"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "rdirectoryCreate User:", "Modified by:" ]
  Fields = [
        """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
        """<Computer>({host}[^<]{1,2000})""",
        """Modified by:({user}.+?)\s{1,100}(\(.+?\))?\s{1,100}\(({domain}[^\/)]{1,2000})""",
	"""User:({account_name}.+?)\s{1,100}\(({account_domain}[^\/)]{1,2000})"""
        """\[Principal Name\]\s{0,100}Add:({account_name}[^@]{1,2000})(@({account_domain}[^.]{1,2000}))?[^\[]{0,2000}\[""",
        """Credentials:({account_used_domain}[^\\]{1,2000})\\+([^\s.]{1,2000}\.)*({account}[^\s.]{1,2000})""",
        """Add:13=({user_type}\d{1,100})\[Employee Type\]"""
  ]
}
```