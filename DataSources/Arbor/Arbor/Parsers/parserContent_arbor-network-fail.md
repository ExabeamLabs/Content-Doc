#### Parser Content
```Java
{
Name = arbor-network-fail
  Vendor = Arbor
  Product = Arbor
  Lms = Splunk
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = ["""arbor-networks-aps:""", """Blocked Host"""]
  Fields = [
     """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
     """\d\d:\d\d:\d\d\s({host}[^\s]{0,2000})\s""",
     """Blocked\shost\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""
     """\sby\s({failure_reason}.+)\susing""",
     """\susing\s({protocol}[^\/]{0,2000})\/\d{1,6}\s"""
     """destination\s({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s""",
     """\ssource\sport\s({src_port}\d{1,6})"""
     """\w+\/({dest_port}\d{1,6})\s\("""
     """\/\d{1,6}\s\(({activity}[^\)]{0,2000})""",
     """arbor-networks-aps:\s{0,100}({outcome}[^:]{0,2000}):\s"""
   ]
}
```