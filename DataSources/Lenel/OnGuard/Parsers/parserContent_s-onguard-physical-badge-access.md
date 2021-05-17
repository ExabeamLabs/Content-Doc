#### Parser Content
```Java
{
Name = s-onguard-physical-badge-access
  Vendor = Lenel
  Product = OnGuard
  Lms = Splunk
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
  Conditions = [ """, EVDESCR="""", """, SSNO="""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\WEVENT_LOCAL_TIME="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """\WLASTNAME="({last_name}[^"]{1,2000}?)\s{0,100}"""",
    """\WFIRSTNAME="({first_name}[^"]{1,2000}?)\s{0,100}"""",
    """\WEVDESCR="({outcome}[^"]{1,2000})""",
    """\WCARDNUM="({badge_id}[^"]{1,2000})""",
    """\WSSNO="({user}[^"]{1,2000})"""",
    """\WSERIALNUM="({serial_num}[^"]{1,2000})""",
    """\WREADERDESC="({location_door}[^"]{1,2000})""",
    """\WDEVID="({devid}[^"]{1,2000})""",
    """\WNAME="({location_building}[^"]{1,2000})""",
    """\WSEQ="({seq_num}[^"]{1,2000})""",
    """({direction}IN|OUT)""",
  ]
}
```