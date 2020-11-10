import XCTest
@testable import CCWrapper

final class CCWrapperTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        XCTAssertEqual(CCWrapper().text, "Hello, World!")
    }

    static var allTests = [
        ("testExample", testExample),
    ]
}
