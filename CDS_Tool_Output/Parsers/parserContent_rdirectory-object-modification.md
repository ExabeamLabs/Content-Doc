#### Parser Content
```Java
{
Name = rdirectory-object-modification
  Vendor = Namespace rDirectory
  Product = Namespace rDirectory
  Lms = Direct
  DataType = "ds-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "rdirectoryModify User:", "Modified by:" ]
  Fields = [
	"""SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
	"""<Computer>({host}[^<]+)""",
	"""Modified by:({user}.+?)\s+(\(.+?\))?\s+\(({domain}[^\/)]+)""",
	"""Credentials:({account_domain}[^\\]+)\\+([^\s.]+\.)*({account}[^\s.]+)""",
	"""rdirectoryModify.+?\(.+?\)\[({attribute}[^\]]+)""",
	"""rdirectoryModify.+?\(.+?\)\[.+?\]\s*Add:({new_attribute}.+?)(\s*To:|<)""",
	"""rdirectoryModify.+?\(.+?\)\[.+?\]\s*Change:({old_attribute}.+?)\s*To:""",
	"""rdirectoryModify.+?\(.+?\)\[.+?\].+?To:({new_attribute}[^<\[]+)""",
	"""rdirectoryModify User:({object}.+?)\s*\("""
  ]
}
```