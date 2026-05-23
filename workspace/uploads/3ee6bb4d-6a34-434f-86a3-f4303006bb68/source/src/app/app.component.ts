import { Component, ElementRef } from '@angular/core';
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
