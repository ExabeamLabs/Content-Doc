#### Parser Content
```Java
{
Name = ensilo-security-alert
  Vendor = EnSilo
  Product = EnSilo
  Lms = Direct
  DataType = "alert"
  TimeFormat = "dd-MMM-yyyy', 'HH:mm:ss"
  Conditions = [ """ enSilo """, """;Raw Data ID:""", """;Rules List:""", """;Severity:""" ]
  Fields = [
    """\s({host}[\w\-.]{1,2000})\s{1,100}enSilo""",
    """\WFirst Seen:\s{0,100}({time}\d{1,100}-\w+-\d{1,100}
```