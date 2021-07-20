#### Parser Content
```Java
{
Name = physical-badge-access-1
  Vendor = Generic Badge Access
  Product = Generic Badge Access
  Lms = Direct
  DataType = "physical-access"
  TimeFormat =  "yyyy-MM-dd HH:mm:ss.S"
  Conditions = [ """, txnconditionName="""", """, cardNumber="""", """, employeeNumber="""", """, datetimeoftxn="""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({host}[\w\-.]{1,2000})\s{1,100}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}""",
    """\Wdatetimeoftxn="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """\Wwherename="({location_door}[^"]{1,2000})""",
    """\WtxnconditionName="({outcome}[^"]{1,2000})""",
    """\Wlastname="({last_name}[^"]{1,2000})""",
    """\WfirstName="({first_name}[^"]{1,2000})""",
    """\WcardNumber="({badge_id}[^"]{1,2000})""",
    """\Wpersonaldata1="({employee_id}[^"]{1,2000})""",
    """\WemployeeNumber="({employee_id}[^"]{1,2000})""",
    """\Wpersonaldata2="({employee_title}[^"]{1,2000})""",
    """\Wpersonaldata10="({employee_type}[^"]{1,2000})""",
  ]
}
```