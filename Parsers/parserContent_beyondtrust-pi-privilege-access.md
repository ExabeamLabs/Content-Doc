#### Parser Content
```Java
{
Name = beyondtrust-pi-privilege-access
    Vendor = BeyondTrust
    Product = BeyondTrust Privileged Identity
    Lms = Direct
    DataType = "privileged-access"
    TimeFormat = "yyyy-dd-MM'T'HH:mm:ss"
    Conditions = [ """sEventID="EVENT_ID_JOB_STARTING_ACCOUNT_ELEVATION_JOB"""", """<Event""", """sOriginatingApplicationName="Privileged Identity"""" ]
    Fields = [
        """\d+:\d+:\d+\s+({host}[^\s]+)\s+<Event""",
        """dtPostTime="({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})""",
        """dwAppSpecificEventID="({event_code}\d+)""",
        """sEventID="({event_name}[^"]+)""", 
        """sOriginatingAccount="(({domain}[^"\\]+)\\+)?({user}[^"]+)""",
        """sOriginatingSystem="({dest_host}[^"]+)""",
        """key="AccountToElevate"\s+value="(({account_domain}[^"\\]+)\\+)?({account}[^"]+)"""
    ]
}
```