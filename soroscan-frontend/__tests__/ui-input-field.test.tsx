import React from "react"
import { render, screen } from "@testing-library/react"
import { InputField } from "@/components/ui/input-field"

describe("InputField", () => {
  it("associates label with the input", () => {
    render(<InputField label="Email" id="email-field" />)
    const input = screen.getByLabelText("Email")
    expect(input).toHaveAttribute("id", "email-field")
  })

  it("shows error message and marks invalid when error is a string", () => {
    render(
      <InputField
        label="Name"
        id="name"
        error="Required"
      />
    )
    const input = screen.getByLabelText("Name")
    expect(input).toHaveAttribute("aria-invalid", "true")
    expect(input).toHaveAttribute("aria-errormessage", "name-error")
    const alert = screen.getByRole("alert")
    expect(alert).toHaveTextContent("Required")
    expect(input).toHaveAttribute("data-state", "error")
  })

  it("passes success state through when valid", () => {
    render(<InputField label="Name" id="name" state="success" />)
    expect(screen.getByLabelText("Name")).toHaveAttribute("data-state", "success")
  })

  it("shows required indicator on the label", () => {
    render(<InputField label="Email" id="email" required />)
    expect(screen.getByText("*")).toBeInTheDocument()
  })

  it("links hint via aria-describedby when there is no error", () => {
    render(
      <InputField
        label="Code"
        id="code"
        hint="Format: XXXX"
      />
    )
    const input = screen.getByLabelText("Code")
    expect(input).toHaveAttribute("aria-describedby", "code-hint")
    expect(screen.getByText("Format: XXXX")).toBeInTheDocument()
  })

  it("does not render hint when error is set", () => {
    render(
      <InputField
        label="Code"
        id="code"
        hint="Should not show"
        error="Bad"
      />
    )
    expect(screen.queryByText("Should not show")).not.toBeInTheDocument()
  })
})
