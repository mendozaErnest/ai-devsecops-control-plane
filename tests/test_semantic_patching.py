import pytest

from src.integrations.github_client import (
    GitHubClientError,
    build_lightweight_patched_content,
    find_java_class_range,
    find_java_method_range,
    find_ts_class_range,
    find_ts_method_range,
)


def test_find_ts_method_range_simple():
    source = """export class AppComponent {
  public sanitizeInput(value: string): string { return value.trim(); }
}"""

    assert find_ts_method_range(source, 2) == (2, 2)


def test_find_ts_method_range_multiline():
    source = """export class AppComponent {
  async fetchData(): Promise<void> {
    const response = await fetch("/api/data");
    const data = await response.json();
    if (data.enabled) {
      console.log(data);
    }
    for (const item of data.items) {
      console.log(item.name);
    }
    this.ready = true;
  }
}"""

    assert find_ts_method_range(source, 7) == (2, 12)


def test_find_ts_method_range_with_decorator():
    source = """export class AppComponent {
  @HostListener("click", ["$event"])
  public handleClick(event: MouseEvent): void {
    event.preventDefault();
  }
}"""

    assert find_ts_method_range(source, 4) == (2, 5)


def test_find_ts_method_range_returns_none_on_ambiguous():
    source = """export const value = "not a method";
const rendered = value.toUpperCase();"""

    assert find_ts_method_range(source, 2) is None


def test_find_ts_class_range():
    source = """@Component({
  selector: "app-root"
})
export class AppComponent {
  title = "demo";
}"""

    assert find_ts_class_range(source, "AppComponent") == (1, 6)


def test_find_java_method_range_simple():
    source = """class AuthService {
    public String hashPassword(String input) {
        return input.trim();
    }
}"""

    assert find_java_method_range(source, 3) == (2, 4)


def test_find_java_method_range_with_throws():
    source = """class AuthService {
    private static boolean validateToken(String token) throws Exception {
        if (token == null) {
            throw new Exception("missing");
        }
        return token.length() > 10;
    }
}"""

    assert find_java_method_range(source, 4) == (2, 7)


def test_find_java_method_range_with_annotation():
    source = """class AuthService {
    @Override
    public String toString() {
        return "AuthService";
    }

    @Test
    public void validatesTokens() {
        assert true;
    }
}"""

    assert find_java_method_range(source, 3) == (2, 5)
    assert find_java_method_range(source, 9) == (7, 10)


def test_find_java_method_range_returns_none_on_ambiguous():
    source = """class AuthService {
    String token = "abc";
    boolean enabled = token.length() > 2;
}"""

    assert find_java_method_range(source, 3) is None


def test_find_java_class_range():
    source = """@Deprecated
public class AuthService {
    private String token;
}"""

    assert find_java_class_range(source, "AuthService") == (1, 4)


def test_guardrail_rejects_overshrunk_file():
    original = "\n".join(f"line {index}" for index in range(1, 101))
    patch = "\n".join(f"patched {index}" for index in range(1, 21))

    with pytest.raises(GitHubClientError, match="below 60%"):
        build_lightweight_patched_content(
            original,
            patch,
            {
                "file_path": "src/app/app.component.ts",
                "line_start": 1,
                "line_end": 100,
            },
            "angular",
        )
