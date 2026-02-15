"""
Vulnerable Gradio Application
=============================
This Gradio app demonstrates vulnerabilities:
- CVE-2024-47867: Path Traversal via file upload naming
- CVE-2024-47168: Path Traversal in file serving
- CVE-2024-47872: Arbitrary File Access via symlink following

Endpoints exposed:
- /upload: File upload (vulnerable to path traversal in filename)
- /file=<path>: File serving (vulnerable to path traversal)
- /api/predict: API endpoint for text processing
"""

import gradio as gr
import os
from pathlib import Path

UPLOAD_DIR = Path("/app/uploads")
FILES_DIR = Path("/app/files")


def process_text(text: str) -> str:
    """Simple text processing function."""
    if not text:
        return "Please enter some text."
    return f"Processed: {text.upper()}\nLength: {len(text)} characters"


def upload_file(file) -> str:
    """
    File upload handler.
    Vulnerable to CVE-2024-47867 - path traversal via filename.
    """
    if file is None:
        return "No file uploaded."

    # Get the uploaded file path
    file_path = Path(file.name)
    filename = file_path.name

    # Save to uploads directory
    save_path = UPLOAD_DIR / filename

    # Copy file content
    with open(file, 'rb') as src:
        content = src.read()

    with open(save_path, 'wb') as dst:
        dst.write(content)

    return f"File uploaded: {filename}\nSize: {len(content)} bytes\nSaved to: {save_path}"


def list_files() -> str:
    """List files in the uploads and files directories."""
    result = ["=== Uploaded Files ==="]

    if UPLOAD_DIR.exists():
        for f in UPLOAD_DIR.iterdir():
            result.append(f"  - {f.name}")
    else:
        result.append("  (no uploads)")

    result.append("\n=== Available Files ===")
    if FILES_DIR.exists():
        for f in FILES_DIR.iterdir():
            result.append(f"  - {f.name}")
    else:
        result.append("  (no files)")

    return "\n".join(result)


def read_file(filename: str) -> str:
    """
    Read a file from the files directory.
    Vulnerable to CVE-2024-47168 - path traversal.
    """
    if not filename:
        return "Please enter a filename."

    # Vulnerable: no path sanitization
    file_path = FILES_DIR / filename

    try:
        with open(file_path, 'r') as f:
            content = f.read()
        return f"=== {filename} ===\n{content}"
    except FileNotFoundError:
        return f"File not found: {filename}"
    except PermissionError:
        return f"Permission denied: {filename}"
    except Exception as e:
        return f"Error reading file: {str(e)}"


# Create Gradio interface
with gr.Blocks(title="Vulnerable Gradio App") as demo:
    gr.Markdown("# Gradio Demo Application")
    gr.Markdown("A simple demo app with text processing and file handling.")

    with gr.Tab("Text Processing"):
        text_input = gr.Textbox(
            label="Enter text",
            placeholder="Type something here..."
        )
        text_output = gr.Textbox(label="Result")
        text_btn = gr.Button("Process")
        text_btn.click(fn=process_text, inputs=text_input, outputs=text_output)

    with gr.Tab("File Upload"):
        file_input = gr.File(label="Select a file to upload")
        upload_output = gr.Textbox(label="Upload Result")
        upload_btn = gr.Button("Upload")
        upload_btn.click(fn=upload_file, inputs=file_input, outputs=upload_output)

    with gr.Tab("File Browser"):
        list_output = gr.Textbox(label="Available Files", lines=10)
        list_btn = gr.Button("List Files")
        list_btn.click(fn=list_files, inputs=[], outputs=list_output)

        gr.Markdown("---")

        filename_input = gr.Textbox(
            label="Filename to read",
            placeholder="Enter filename (e.g., public.txt)"
        )
        file_content = gr.Textbox(label="File Content", lines=5)
        read_btn = gr.Button("Read File")
        read_btn.click(fn=read_file, inputs=filename_input, outputs=file_content)

    gr.Markdown("---")
    gr.Markdown("*Gradio version: 4.19.0*")


if __name__ == "__main__":
    # Launch with sharing disabled but accessible from network
    demo.launch(
        server_name="0.0.0.0",
        server_port=7860,
        share=False
    )
