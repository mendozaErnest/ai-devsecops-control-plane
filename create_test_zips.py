import os
import shutil
import zipfile


PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
BUILD_ROOT = os.path.join(PROJECT_ROOT, ".test_zip_build")

ANGULAR_LAB_NAME = "angular-vuln-lab"
JAVA_LAB_NAME = "java-vuln-lab"


ANGULAR_COMPONENT_TS = """import { Component, ElementRef } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html'
})
export class AppComponent {
  constructor(private sanitizer: DomSanitizer, private element: ElementRef) {}

  vulnerableMethod(userInput: string) {
    // Gatillo 1: bypassSecurityTrustHtml
    this.trusted = this.sanitizer.bypassSecurityTrustHtml(userInput);
    // Gatillo 2: innerHTML nativo sin sanitizar
    this.element.nativeElement.innerHTML = userInput;
  }
}
"""


ANGULAR_COMPONENT_HTML = """<div [innerHTML]="commentFromUser"></div>
"""


ANGULAR_ENVIRONMENT_TS = """// Gatillo 4 y 5: Secretos expuestos y CORS laxo
export const environment = {
  production: false,
  apiKey: "ABCDEF1234567890SECRET_TOKEN",
  allowedOrigins: ["*"],
  corsConfig: 'origin: "*"'
};
"""


JAVA_VULNERABLE_APP = """package com.example;

import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.security.KeyPairGenerator;
import javax.crypto.Cipher;
import java.sql.Statement;

public class VulnerableApp {
    public void executeRiskOperations(Object input, String user, Statement stmt) throws Exception {
        // Gatillo 1 y 2: Criptografía obsoleta (Cosecha ahora, descifra después)
        MessageDigest md1 = MessageDigest.getInstance("SHA-1");
        MessageDigest md2 = MessageDigest.getInstance("MD5");

        // Gatillo 3: Llave RSA peligrosamente corta
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);

        // Gatillo 4: Inyección SQL clásica por concatenación
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");

        // Gatillo 5: Deserialización destructiva de objetos
        ObjectInputStream ois = new ObjectInputStream((java.io.InputStream) input);
    }
}
"""


def write_file(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w", encoding="utf-8") as target:
        target.write(content)


def zip_directory(source_dir, zip_path):
    if os.path.exists(zip_path):
        os.remove(zip_path)

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for current_root, _directories, files in os.walk(source_dir):
            for filename in files:
                absolute_path = os.path.join(current_root, filename)
                archive_name = os.path.relpath(absolute_path, source_dir)
                archive.write(absolute_path, archive_name)


def build_angular_lab():
    lab_root = os.path.join(BUILD_ROOT, ANGULAR_LAB_NAME)
    write_file(
        os.path.join(lab_root, "src", "app", "app.component.ts"),
        ANGULAR_COMPONENT_TS,
    )
    write_file(
        os.path.join(lab_root, "src", "app", "app.component.html"),
        ANGULAR_COMPONENT_HTML,
    )
    write_file(
        os.path.join(lab_root, "src", "environments", "environment.ts"),
        ANGULAR_ENVIRONMENT_TS,
    )
    zip_path = os.path.join(PROJECT_ROOT, f"{ANGULAR_LAB_NAME}.zip")
    zip_directory(lab_root, zip_path)
    print(f"Created {zip_path}")


def build_java_lab():
    lab_root = os.path.join(BUILD_ROOT, JAVA_LAB_NAME)
    write_file(
        os.path.join(lab_root, "src", "main", "java", "com", "example", "VulnerableApp.java"),
        JAVA_VULNERABLE_APP,
    )
    zip_path = os.path.join(PROJECT_ROOT, f"{JAVA_LAB_NAME}.zip")
    zip_directory(lab_root, zip_path)
    print(f"Created {zip_path}")


def main():
    if os.path.exists(BUILD_ROOT):
        shutil.rmtree(BUILD_ROOT)

    try:
        os.makedirs(BUILD_ROOT, exist_ok=True)
        build_angular_lab()
        build_java_lab()
    finally:
        shutil.rmtree(BUILD_ROOT, ignore_errors=True)

    print("Test ZIP labs are ready in the project root.")


if __name__ == "__main__":
    main()
