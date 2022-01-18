#### Parser Content
```Java
{
Name = cas-login-success
  DataType = "app-login"
  Conditions = ["""ACTION: AUTHENTICATION_SUCCESS""", """ACTION: """, """WHO: """, """WHEN: """, """CLIENT IP ADDRESS: """, """SERVER IP ADDRESS: """]
  Fields = ${CASParserTemplates.cas-template.Fields} [
  ]

cas-template = {
    Vendor = Microsoft
    Product = Microsoft Cloud App Security (MCAS)
    Lms = Splunk
    TimeFormat = "EEE MMM dd HH:mm:ss zzz yyyy"
    Fields = [
      """exabeam_host=({host}[\w\-.]{1,2000})""",
      """WHEN: ({time}\w+ \w+ \d\d \d\d:\d\d:\d\d \w+ \d{1,100})"""
      """CLIENT IP ADDRESS: ({src_ip}[a-fA-F:\d.]{1,2000})"""
      """SERVER IP ADDRESS: ({dest_ip}[a-fA-F:\d.]{1,2000})"""
      """APPLICATION: ({app}[^#]{1,2000})(\s{1,100}|#)?\w+:"""
      """WHO: (audit:unknown|({user}[^#\s@]{1,2000})(@({domain}[^#\s]{1,2000}))?)"""
      """WHAT: ({additional_info}.*?)(\s{1,100}|#\d{1,100})?ACTION:"""
      """ACTION: ({activity}[^#\s]{1,2000})"""
      """service=({object}[^,]{1,2000})"""
    ]
    DupFields = ["domain->email_domain"
}
```