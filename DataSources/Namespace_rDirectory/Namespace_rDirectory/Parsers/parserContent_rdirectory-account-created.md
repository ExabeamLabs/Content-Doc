#### Parser Content
```Java
{
Name = rdirectory-account-created
  Vendor = Namespace rDirectory
  Lms = Direct
  DataType = "account-creation"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "rdirectoryCreate User:", "Modified by:" ]
  Fields = [
        """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
        """<Computer>({host}[^<]+)""",
        """Modified by:({user}.+?)\s+(\(.+?\))?\s+\(({domain}[^\/)]+)""",
	"""User:({account_name}.+?)\s+\(({account_domain}[^\/)]+)"""
        """\[Principal Name\]\s*Add:({account_name}[^@]+)(@({account_domain}[^.]+))?[^\[]*\[""",
        """Credentials:({account_used_domain}[^\\]+)\\+([^\s.]+\.)*({account}[^\s.]+)"""
  ]
}
```