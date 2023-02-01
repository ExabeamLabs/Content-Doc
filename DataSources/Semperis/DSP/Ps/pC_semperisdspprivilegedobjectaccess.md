#### Parser Content
```Java
{
Name = semperis-dsp-privileged-object-access
  Vendor = Semperis
  Product = DSP
  Lms = Splunk
  DataType = "privileged-object-access"
  TimeFormat = "dd/MMM/yyyy HH:mm:ss.SSSS"
  Conditions = [  """Security indicator passed:""", """Permission changes""", """Result: """, """Forest name:""" ]
  Fields = [
    """({event_name}Permission changes)""",
    """Permission changes on ({object}[^:]{1,2000}?) object""",
    """Result:\s{0,100}({outcome}[\S]{1,2000})""",
    """Domains:\s{0,100}({domain}[^:]{1,2000}?)\s\w+?:""",
    """Severity:\s{0,100}({alert_severity}[^:]{1,2000}?)\s\w+?:""",
    """Security indicator passed:\s{0,100}({additional_info}[^:]{1,2000}?)\s{1,100}Generation time:"""
  ]


}
```