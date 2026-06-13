import VSEL.Checker.Certificate

namespace VSEL.Checker

def renderError : CertificateError → String
  | .empty => "empty certificate"
  | .badHeader => "invalid certificate header"
  | .malformedLine line => "malformed certificate line: " ++ line
  | .duplicateField key => "duplicate certificate field: " ++ key
  | .missingField key => "missing certificate field: " ++ key
  | .invalidField key reason => "invalid certificate field " ++ key ++ ": " ++ reason
  | .missingObligation name => "missing semantic obligation: " ++ name

def runMain (args : List String) : IO Unit := do
  match args with
  | [path] =>
      let text ← IO.FS.readFile path
      match checkCertificateText text with
      | Except.ok () =>
          IO.println "VSEL semantic certificate accepted"
      | Except.error err =>
          throw <| IO.userError ("VSEL semantic certificate rejected: " ++ renderError err)
  | _ =>
      throw <| IO.userError "usage: vselCheck <semantic-certificate-file>"

end VSEL.Checker

def main (args : List String) : IO Unit :=
  VSEL.Checker.runMain args
