from conan import ConanFile
from conan.tools.cmake import cmake_layout, CMakeToolchain, CMakeDeps

class ConanApplication(ConanFile):
    package_type = "application"
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeDeps"
    options = {
        "tests": [True, False],
        "sentry": [True, False],
    }
    default_options = {
        "tests": True,
        "sentry": True,
    }
    name = 'metre'
    version = '3.0.0'

    def layout(self):
        cmake_layout(self)

    def configure(self):
        if self.options.sentry:
            self.options["sentry-native"].backend = "inproc"

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["METRE_SENTRY"] = self.options.sentry
        tc.variables["METRE_BUILD_TESTS"] = self.options.tests
        tc.user_presets_path = False
        tc.generate()

    def requirements(self):
        requirements = self.conan_data.get('requirements', [])
        for requirement in requirements:
            self.requires(requirement)
        if self.options.sentry:
            self.requires("sentry-native/0.7.11")
        if self.options.tests:
            self.requires("gtest/1.12.1")
