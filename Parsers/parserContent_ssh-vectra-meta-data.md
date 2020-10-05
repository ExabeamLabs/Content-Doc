#### Parser Content
```Java
{
Name = ssh-vectra-meta-data
  DataType = "remote-logon"
  Conditions = [ """vectra_metadata_ssh""", """METADATA_SSH""" ]
  Fields = ${VectraParserTemplates.vectra-meta-data.Fields} [
    """server="+({server_version}[^"]+)"+""",
    """client="+({client_version}[^"]+)"+""",
    """cipher_alg="+({cipher_algorithm}[^"]+)"+""",
    """compression_alg="+(none|({compression_algotithm}[^"]+))"+"""
  ]
}
```