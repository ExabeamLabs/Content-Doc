#### Parser Content
```Java
{
Name = physical-badge-access-1
  Vendor = Unknown
  Product = Unknown
  Lms = Direct
  DataType = "physical-access"
  TimeFormat =  "yyyy-MM-dd HH:mm:ss.S"
  Conditions = [ """, txnconditionName="""", """, cardNumber="""", """, employeeNumber="""", """, datetimeoftxn="""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({host}[\w\-.]+)\s+\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+""",
    """\Wdatetimeoftxn="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)""",
    """\Wwherename="({location_door}[^"]+)""",
    """\WtxnconditionName="({outcome}[^"]+)""",
    """\Wlastname="({last_name}[^"]+)""",
    """\WfirstName="({first_name}[^"]+)""",
    """\WcardNumber="({badge_id}[^"]+)""",
    """\Wpersonaldata1="({employee_id}[^"]+)""",
    """\WemployeeNumber="({employee_id}[^"]+)""",
    """\Wpersonaldata2="({employee_title}[^"]+)""",
    """\Wpersonaldata10="({employee_type}[^"]+)""",
  ]
}
```