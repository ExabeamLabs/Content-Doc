#### Parser Content
```Java
{
Name = cds-user-login
  Product = CDS
  Conditions = [ """AUDIT:""", """ uid=""", """type=USER_LOGIN""" ]
  DataType = "remote-logon"

cds-user-activity = {
     Vendor = CDS
     Lms = Splunk
     TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
     DataType = "remote-logon"
     Fields = [
       """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
       """exe="({process}[^"]{0,2000})"""",
       """\suid=({user_id}[^\s]{0,2000})\s""",
       """\stype=({activity_type}[^\s]{0,2000})\s""",
       """\d\d:\d\d:\d\d(\.\S+)?\s({host}[^\s]{1,100})\s""",
       """\sexe="({process_directory}.+\/)({process_name}.+?)"""",
       """\spid=({pid}[^\s]{1,2000})\s""",
       """\sauid=({account_used_id}[^\s]{1,2000})\s"""
       """addr=({dest_host}[^\s]{1,2000})\s""",
       """acct="({account}[^"]{1,2000})"""",
       """res=({outcome}failed|success)"""
     ]
     DupFields = [ "process_directory->directory"
}
```