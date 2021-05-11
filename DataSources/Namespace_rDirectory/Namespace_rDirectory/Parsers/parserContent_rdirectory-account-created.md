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
        """<Computer>({host}[^<]+)""",
        """Modified by:({user}.+?)\s{1,100}(\(.+?\))?\s{1,100}\(({domain}[^\/)]+)""",
	"""User:({account_name}.+?)\s{1,100}\(({account_domain}[^\/)]+)"""
        """\[Principal Name\]\s{0,100}Add:({account_name}[^@]+)(@({account_domain}[^.]+))?[^\[]*\[""",
        """Credentials:({account_used_domain}[^\\]+)\\+([^\s.]+\.)*({account}[^\s.]+)""",
        """Add:13=({user_type}\d{1,100})\[Employee Type\]"""
  ]
}
```