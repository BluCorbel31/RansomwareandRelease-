import tkinter as tk
from PIL import Image, ImageTk
import language_tool_python

spell_checker = language_tool_python.LanguageTool('en-US')

def word_count(text):
    # Split the text into words
    words = text.split()
    # Count the number of words
    word_count = len(words)
    return word_count

def highlight_misspelled_words(text):
    # Split the text into words
    words = text.split()
    # Find misspelled words
    misspelled_words = spell_checker.unknown(words)
    # Highlight misspelled words in the text
    highlighted_text = text
    for word in misspelled_words:
        highlighted_text = highlighted_text.replace(word, f'***{word}***')
    return highlighted_text

def correct_punctuation_and_grammar(text, language='en-US'):
    tool = language_tool_python.LanguageTool(language)
    # Auto-correct punctuation and grammar
    matches = tool.check(text)
    corrected_text = language_tool_python.utils.correct(text, matches)
    return corrected_text

def analyze_text(text, language='en-US'):
    # Perform text analysis
    word_count_result = word_count(text)
    corrected_text = correct_punctuation_and_grammar(text, language)
    highlighted_text = highlight_misspelled_words(corrected_text)
    # Return the analysis result
    return {"word_count": word_count_result, "corrected_text": corrected_text, "highlighted_text": highlighted_text}

# Function to retrieve the flag image based on the language
def get_flag_image(language):
    # Dictionary mapping languages to flag file paths
    language_flags = {
        'en-US': 'flags/us_flag.png',
        'fr': 'flags/france_flag.png',
        'es': 'flags/spain_flag.png',
        # Add more languages and flag paths as needed
    }
    # Check if the language is in the dictionary
    if language in language_flags:
        flag_path = language_flags[language]
        return Image.open(flag_path)
    else:
        # If language not found, return a default flag image
        return Image.open('flags/default_flag.png')

# Function to display the flag image in the GUI
def display_flag(language):
    flag_image = get_flag_image(language)
    flag_image = flag_image.resize((200, 100), Image.ANTIALIAS)
    flag_photo = ImageTk.PhotoImage(flag_image)

    # Create a Tkinter window
    root = tk.Tk()
    root.title("Country Flag")
    
    # Display the flag image
    flag_label = tk.Label(root, image=flag_photo)
    flag_label.image = flag_photo
    flag_label.pack(padx=20, pady=20)
    
    # Run the Tkinter event loop
    root.mainloop()

# Example usage:
text_to_analyze = "This is a sampple texxt forr word count analyssi."
analysis_result = analyze_text(text_to_analyze, language='en-US')
print(analysis_result)

# Display the flag based on the language used for analysis
language = 'en-US'  # Change the language code as needed
display_flag(language)