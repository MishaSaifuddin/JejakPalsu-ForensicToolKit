import os
import numpy as np
from PIL import Image, ImageChops, ImageEnhance
import cv2

def ela_analysis(image_path, quality=90, scale=10):
    """
    Performs Error Level Analysis (ELA) on an image to detect tampering.
    ELA works by resaving a JPEG image at a specified quality and
    calculating the absolute difference (error) between the original and
    resaved image. Tampered areas usually show a higher, more distinct error level.

    Args:
        image_path (str): Path to the input image (preferably JPEG).
        quality (int): JPEG quality level for re-saving (e.g., 90).
        scale (int): Factor to scale up the error image for better visualization.

    Returns:
        Image: A PIL Image object of the ELA result, or None on error.
    """
    try:
        # 1. Load Original Image
        original_img = Image.open(image_path).convert('RGB')
        
        # 2. Save a Recompressed Copy
        temp_file = "temp_ela_copy.jpg"
        original_img.save(temp_file, 'JPEG', quality=quality)
        
        # 3. Load the Recompressed Copy
        resaved_img = Image.open(temp_file).convert('RGB')
        
        # 4. Calculate the Absolute Difference (Error Level)
        # ImageChops.difference returns the difference between two images.
        ela_img = ImageChops.difference(original_img, resaved_img)
        
        # 5. Enhance the Error Image for Visibility (Normalization)
        extrema = ela_img.getextrema()
        max_diff = max([ex[1] for ex in extrema])
        
        if max_diff == 0:
            print("No difference found, image is likely pristine or not JPEG.")
            return ela_img
        
        # Normalize the difference to 0-255 range and apply a scale factor
        scale_factor = 255.0 / max_diff
        ela_img = ImageEnhance.Brightness(ela_img).enhance(scale_factor)
        
        # 6. Optional: Increase contrast/brightness for better visualization
        ela_img = ImageEnhance.Contrast(ela_img).enhance(1.5)
        
        # 7. Clean up the temporary file
        os.remove(temp_file)
        
        return ela_img

    except Exception as e:
        print(f"An error occurred during ELA: {e}")
        if os.path.exists(temp_file):
             os.remove(temp_file)
        return None

def main_tamper_check(file_path):
    print(f"--- Running Digital Forensics Check on: {file_path} ---")
    
    # --- 1. Error Level Analysis (ELA) ---
    ela_result = ela_analysis(file_path)
    
    if ela_result:
        # Display the ELA image
        # In a real app, you would save this or show it in a GUI.
        ela_result.save("ELA_Result_" + os.path.basename(file_path))
        print(f"[SUCCESS] ELA result saved as ELA_Result_{os.path.basename(file_path)}")
        print("Tampered regions will appear brighter and more inconsistent in the ELA result.")
    
    # --- 2. Metadata Extraction (Simplified like ExifTool) ---
    try:
        from PIL.ExifTags import TAGS
        img = Image.open(file_path)
        exif_data = img._getexif()
        
        if exif_data:
            print("\n[INFO] Found EXIF Metadata:")
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                # Print only relevant tags to keep it clean
                if isinstance(tag, str) and tag in ['DateTimeOriginal', 'Make', 'Model', 'Software']:
                    print(f"    {tag:20}: {value}")
            
            # --- Forensic Metadata Check ---
            if 'Software' in [TAGS.get(k) for k in exif_data.keys()]:
                 software = [v for k, v in exif_data.items() if TAGS.get(k) == 'Software']
                 if any('Photoshop' in s or 'GIMP' in s for s in software):
                     print("[ALERT] 'Software' tag suggests editing: ", software)
            
        else:
             print("\n[INFO] No significant EXIF Metadata found.")
    
    except Exception as e:
        print(f"\n[ERROR] Metadata check failed: {e}")

# Example Usage (replace 'path/to/your/document.jpg' with a real file)
# To test, save a JPEG, then open it in an editor (like MS Paint or Photoshop), 
# make a small change, and re-save it. The edited region should show up brighter in the ELA result.
# main_tamper_check('path/to/your/document.jpg')