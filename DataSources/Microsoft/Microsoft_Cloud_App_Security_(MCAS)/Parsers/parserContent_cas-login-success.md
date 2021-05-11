#### Parser Content
```Java
{
Name = cas-login-success
  DataType = "app-login"
  Conditions = ["""ACTION: AUTHENTICATION_SUCCESS""", """ACTION: """, """WHO: """, """WHEN: """, """CLIENT IP ADDRESS: """, """SERVER IP ADDRESS: """]
  Fields = ${CASParserTemplates.cas-template.Fields} [
  ]
}
cas-template = {
    Vendor = Microsoft
    Product = Microsoft Cloud App Security (MCAS)
    Lms = Splunk
    TimeFormat = "EEE MMM dd HH:mm:ss zzz yyyy"
    Fields = [
      """exabeam_host=({host}[\w\-.]+)""",
      """WHEN: ({time}\w+ \w+ \d\d \d\d:\d\d:\d\d \w+ \d{1,100})"""
      """CLIENT IP ADDRESS: ({src_ip}[a-fA-F:\d.]+)"""
      """SERVER IP ADDRESS: ({dest_ip}[a-fA-F:\d.]+)"""
      """APPLICATION: ({app}[^#]+)(\s{1,100}|#)?\w+:"""
      """WHO: (audit:unknown|({user}[^#\s@]+)(@({domain}[^#\s]+))?)"""
      """WHAT: ({additional_info}.*?)(\s{1,100}|#\d{1,100})?ACTION:"""
      """ACTION: ({activity}[^#\s]+)"""
      """service=({object}[^,]+)"""
    ]

```