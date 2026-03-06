import os
import random
class Card Generator:
    def __init__(self, card_type, card_number=None):
        self.card_type = card_type
        self.card_number = card_number or self.generate_number_by_type(card_type)

    def generate_number_by_type(self, card_type):
        prefix = ""
        if card_type.lower() == "visa":
            prefix = random.choice(["4"])
        elif card_type.lower() == "mastercard":
            prefix = random.choice(["51", "52", "53", "54", "55"])
        elif card_type.lower() == "amex" or card_type.lower() == "american express":
            prefix = random.choice(["34", "37"])
        elif card_type.lower() == "discover":
            prefix = random.choice(["6011", "65"])
        elif card_type.lower() == "jcb":
            prefix = "35"
        elif card_type.lower() == "diners club":
            prefix = random.choice(["36", "38"])
        elif card_type.lower() == "china unionpay":
            prefix = random.choice([str(i) for i in range(6200, 6250)])
        
        # Generate remaining digits (total length depends on card type)
        length = 16  # Default length for most cards
        if card_type.lower() == "amex" or card_type.lower() == "american express":
            length = 15
        elif card_type.lower() == "diners club":
            length = 14
            
        remaining_digits = length - len(prefix)
        random_digits = ''.join([str(random.randint(0, 9)) for _ in range(remaining_digits)])
        
        return f"{prefix}{random_digits}"

    def generate_card(self):
        return f"{self.card_type} Card Number: {self.card_number}"
    
    def MerchantCode(self):
        # Using the Merchant Category Codes from the document
        mcc_categories = {
            "Agricultural Services": ["0742", "0763", "0780"],
            "Contracted Services": ["1520", "1711", "1731", "1740", "1750", "1761", "1771", "1799", "2741", "2791", "2842"],
            "Transportation Services": ["4011", "4111", "4112", "4119", "4121", "4131", "4214", "4215", "4225", "4411", "4457", "4468", "4511", "4582", "4722", "4784", "4789"],
            "Utility Services": ["4812", "4814", "4816", "4821", "4829", "4899", "4900"],
            "Retail Outlet Services": ["5013", "5021", "5039", "5044", "5045", "5046", "5047", "5051", "5065", "5072", "5074", "5085", "5094", "5099", "5111", "5122", "5131", "5137", "5139", "5169", "5172", "5192", "5193", "5198", "5199", "5200", "5211", "5231", "5251", "5261", "5271", "5300", "5309", "5310", "5311", "5331", "5399", "5411", "5422", "5441", "5451", "5462", "5499", "5511", "5521", "5532", "5533", "5541", "5542", "5551", "5561", "5571", "5592", "5598", "5599"]
        }
        
        # Randomly select a category and then a code from that category
        category = random.choice(list(mcc_categories.keys()))
        code = random.choice(mcc_categories[category])
        
        return f"{code} - {category}"
    
    def display_card(self):
        print(self.generate_card())
        print(f"Merchant Category Code: {self.MerchantCode()}")
    def _load_merchant_codes(self):
        """Load merchant category codes from predefined categories"""
        # Agricultural Services (0001-1499)
        self.merchant_category_codes.update({
            "0742": "Veterinary Services",
            "0763": "Agricultural Cooperatives",
            "0780": "Horticultural and Landscaping Services"
        })
        
        # Contracted Services (1500-2999)
        self.merchant_category_codes.update({
            "1520": "General Contractors–Residential and Commercial",
            "1711": "Air Conditioning, Heating and Plumbing Contractors",
            "1731": "Electrical Contractors",
            "1740": "Insulation, Masonry, Plastering, Stonework and Tile Setting Contractors",
            "1750": "Carpentry Contractors",
            "1761": "Roofing and Siding, Sheet Metal Work Contractors",
            "1771": "Concrete Work Contractors",
            "1799": "Contractors, Special Trade Contractors–not elsewhere classified",
            "2741": "Miscellaneous Publishing and Printing",
            "2791": "Typesetting, Plate Making and Related Services",
            "2842": "Specialty Cleaning, Polishing and Sanitation Preparations"
        })
        
        # Airlines (3000-3299)
        self.merchant_category_codes.update({
            "3000": "United Airlines",
            "3001": "American Airlines",
            "3002": "Pan American",
            "3003": "Eurofly Airlines",
            "3004": "Dragon Airlines",
            "3005": "British Airways",
            "3006": "Japan Airlines",
            "3007": "Air France",
            "3008": "Lufthansa",
            "3009": "Air Canada",
            "3010": "KLM (Royal Dutch Airlines)",
            "3011": "Aeroflot",
            "3012": "Qantas",
            "3013": "ITA Airways (Formerly Alitalia)",
            "3014": "Saudi Arabian Airlines",
            "3026": "Emirates Airlines",
            "3058": "Delta",
            "3066": "Southwest",
            "3070": "Flydubai",
            "3080": "Swoop Inc",
            "3082": "Korean Airlines",
            "3099": "Cathay Pacific",
            "3144": "Virgin Atlantic",
            "3168": "Hainan Airlines",
            "3169": "Riyadh Air",
            "3174": "Jetblue Airways",
            "3256": "Alaska Airlines"
        })
        
        # Car Rental (3300-3499)
        self.merchant_category_codes.update({
            "3351": "Affiliated Auto Rental",
            "3352": "American Intl Rent-A-Car",
            "3353": "Brooks Rent-A-Car",
            "3354": "Action Auto Rental",
            "3355": "Sixt Car Rental",
            "3357": "Hertz",
            "3359": "Payless Car Rental",
            "3366": "Budget Rent-A-Car",
            "3387": "Alamo Rent-A-Car",
            "3389": "Avis Rent-A-Car",
            "3390": "Dollar Rent-A-Car",
            "3393": "National Car Rental",
            "3395": "Thrifty Car Rental",
            "3405": "Enterprise Rent-A-Car",
            "3441": "Advantage Rent-A-Car"
        })
        
        # Lodging (3500-3999)
        self.merchant_category_codes.update({
            "3501": "Holiday Inns",
            "3502": "Best Western Hotels",
            "3503": "Sheraton",
            "3504": "Hilton Hotels",
            "3509": "Marriott",
            "3510": "Days Inns",
            "3512": "Inter-Continental Hotels",
            "3513": "Westin",
            "3615": "Travelodge",
            "3640": "Hyatt Hotels",
            "3649": "Radisson Hotels",
            "3700": "Motel 6",
            "3710": "The Ritz-Carlton",
            "3750": "Crowne Plaza Hotels",
            "3780": "Disney Resorts",
            "3807": "Element",
            "3812": "Hyatt Place",
            "3813": "Hotel Indigo",
            "3824": "Aria",
            "3825": "Vdara",
            "3828": "Cosmopolitan of Las Vegas",
            "3831": "Waldorf",
            "3834": "Baymont Inn & Suites",
            "3835": "Dolce Hotels and Resorts",
            "3836": "Hawthorn by Wyndham",
            "3837": "Hoshino Resorts",
            "3838": "Kimpton Hotels",
            "3839": "Kyoritsu Hotels",
            "3840": "Rio Hotels"
        })
        
        # Transportation Services (4000-4799)
        self.merchant_category_codes.update({
            "4011": "Railroads",
            "4111": "Local and Suburban Commuter Passenger Transportation, Including Ferries",
            "4112": "Passenger Railways",
            "4119": "Ambulance Services",
            "4121": "Taxicabs and Limousines",
            "4131": "Bus Lines",
            "4214": "Motor Freight Carriers and Trucking – Local and Long Distance, Moving and Storage Companies, and Local Delivery Services",
            "4215": "Courier Services – Air and Ground, and Freight Forwarders",
            "4225": "Public Warehousing and Storage – Farm Products, Refrigerated Goods, Household Goods, and Storage",
            "4411": "Steamship and Cruise Lines",
            "4457": "Boat Rentals and Leasing",
            "4468": "Marinas, Marine Service, and Supplies",
            "4511": "Airlines and Air Carriers (Not Elsewhere Classified)",
            "4582": "Airports, Flying Fields, and Airport Terminals",
            "4722": "Travel Agencies and Tour Operators",
            "4723": "Package Tour Operators – Germany Only",
            "4784": "Tolls and Bridge Fees",
            "4789": "Transportation Services (Not Elsewhere Classified)"
        })
        
        # Utility Services (4800-4999)
        self.merchant_category_codes.update({
            "4812": "Telecommunication Equipment and Telephone Sales",
            "4814": "Telecommunication Services, including Local and Long-Distance Calls, Credit Card Calls, Calls Through Use of Magnetic Stripe-Reading Telephones, and Fax Services",
            "4816": "Computer Network/Information Services",
            "4821": "Telegraph Services",
            "4829": "Money Transfer",
            "4899": "Cable, Satellite and Other Pay Television/Radio/Streaming Services",
            "4900": "Utilities – Electric, Gas, Water, and Sanitary"
        })
        
        # Retail (5000-5599)
        self.merchant_category_codes.update({
            "5013": "Motor Vehicle Supplies and New Parts",
            "5021": "Office and Commercial Furniture",
            "5039": "Construction Materials (Not Elsewhere Classified)",
            "5044": "Photographic, Photocopy, Microfilm Equipment and Supplies",
            "5045": "Computers and Computer Peripheral Equipment and Software",
            "5046": "Commercial Equipment (Not Elsewhere Classified)",
            "5047": "Medical, Dental, Ophthalmic and Hospital Equipment and Supplies",
            "5051": "Metal Service Centers and Offices",
            "5065": "Electrical Parts and Equipment",
            "5072": "Hardware, Equipment and Supplies",
            "5074": "Plumbing and Heating Equipment and Supplies",
            "5085": "Industrial Supplies (Not Elsewhere Classified)",
            "5094": "Precious Stones and Metals, Watches and Jewelry",
            "5099": "Durable Goods (Not Elsewhere Classified)",
            "5111": "Stationery, Office Supplies, Printing and Writing Paper",
            "5122": "Drugs, Drug Proprietaries, and Druggist Sundries",
            "5131": "Piece Goods, Notions, and Other Dry Goods",
            "5137": "Men's, Women's, and Children's Uniforms and Commercial Clothing",
            "5139": "Commercial Footwear",
            "5169": "Chemicals and Allied Products (Not Elsewhere Classified)",
            "5172": "Petroleum and Petroleum Products",
            "5192": "Books, Periodicals and Newspapers",
            "5193": "Florists Supplies, Nursery Stock and Flowers",
            "5198": "Paints, Varnishes and Supplies",
            "5199": "Nondurable Goods (Not Elsewhere Classified)",
            "5200": "Home Supply Warehouse Stores",
            "5211": "Lumber and Building Materials Stores",
            "5231": "Glass, Paint, and Wallpaper Stores",
            "5251": "Hardware Stores",
            "5261": "Nurseries and Lawn and Garden Supply Stores",
            "5262": "Marketplaces",
            "5271": "Mobile Home Dealers",
            "5300": "Wholesale Clubs",
            "5309": "Duty Free Stores",
            "5310": "Discount Stores",
            "5311": "Department Stores",
            "5331": "Variety Stores",
            "5399": "Miscellaneous General Merchandise",
            "5411": "Grocery Stores and Supermarkets",
            "5422": "Freezer and Locker Meat Provisioners",
            "5441": "Candy, Nut and Confectionery Stores",
            "5451": "Dairy Products Stores",
            "5462": "Bakeries",
            "5499": "Miscellaneous Food Stores–Convenience Stores, Markets, Specialty Stores",
            "5511": "Automobile and Truck Dealers–Sales, Service, Repairs, Parts and Leasing",
            "5521": "Automobile and Truck Dealers–(Used Only)–Sales",
            "5532": "Automotive Tire Stores",
            "5533": "Automotive Parts and Accessories Stores",
            "5541": "Service Stations (With or Without Ancillary Services)",
            "5542": "Fuel Dispenser, Automated",
            "5551": "Boat Dealers",
            "5561": "Camper, Recreational and Utility Trailer Dealers",
            "5571": "Motorcycle Dealers",
            "5592": "Motor Home Dealers",
            "5598": "Snowmobile Dealers",
            "5599": "Miscellaneous Automotive, Aircraft, and Farm Equipment Dealers (Not Elsewhere Classified)"
        })
        
        # Clothing Stores (5600-5699)
        self.merchant_category_codes.update({
            "5611": "Men's and Boys' Clothing and Accessories Stores",
            "5621": "Women's Ready-To-Wear Stores",
            "5631": "Women's Accessory and Specialty Shops",
            "5641": "Children's and Infants' Wear Stores",
            "5651": "Family Clothing Stores",
            "5655": "Sports and Riding Apparel Stores",
            "5661": "Shoe Stores",
            "5681": "Furriers and Fur Shops",
            "5691": "Men's and Women's Clothing Stores",
            "5697": "Tailors, Seamstresses, Mending, and Alterations",
            "5698": "Wig and Toupee Shops",
            "5699": "Miscellaneous Apparel and Accessory Shops"
        })
        
        # Restaurants and Food (5800-5899)
        self.merchant_category_codes.update({
            "5811": "Caterers",
            "5812": "Eating Places and Restaurants",
            "5813": "Bars, Cocktail Lounges, Discotheques, Nightclubs and Taverns",
            "5814": "Fast Food Restaurants",
            "5815": "Digital Goods: Books, Movies, Music",
            "5816": "Digital Goods: Games",
            "5817": "Digital Goods: Applications (Excludes Games)",
            "5818": "Digital Goods: Large Digital Goods Merchant"
        })
        
        # Miscellaneous Stores (5900-7299)
        self.merchant_category_codes.update({
            "5912": "Drug Stores and Pharmacies",
            "5921": "Package Stores–Beer, Wine and Liquor",
            "5931": "Used Merchandise and Secondhand Stores",
            "5932": "Antique Shops",
            "5933": "Pawn Shops",
            "5935": "Wrecking and Salvage Yards",
            "5937": "Antique Reproduction Stores",
            "5940": "Bicycle Shops–Sales and Service",
            "5941": "Sporting Goods Stores",
            "5942": "Book Stores",
            "5943": "Stationery Stores, Office and School Supply Stores",
            "5944": "Jewelry Stores, Watches, Clocks and Silverware Stores",
            "5945": "Game, Toy and Hobby Shops",
            "5946": "Camera and Photographic Supply Stores",
            "5947": "Gift, Card, Novelty and Souvenir Shops",
            "5948": "Luggage and Leather Goods Stores",
            "5949": "Sewing, Needlework, Fabric and Piece Goods Stores",
            "5950": "Crystal and Glassware Stores",
            "5960": "Direct Marketing Insurance Services",
            "5962": "Direct Marketing – Travel Related Arrangement Services",
            "5963": "Door-to-Door Sales",
            "5964": "Direct Marketing–Catalog Merchants",
            "5965": "Direct Marketing–Combination Catalog and Retail Merchant",
            "5966": "Direct Marketing–Outbound Telemarketing Merchants",
            "5967": "Direct Marketing–Inbound Telemarketing Merchants",
            "5968": "Direct Marketing–Continuity/Subscription Merchant",
            "5969": "Direct Marketing–Other Direct Marketers–Not Elsewhere Classified",
            "5970": "Artist Supply Stores, Craft Shops",
            "5971": "Art Dealers and Galleries",
            "5972": "Stamp and Coin Stores–Philatelic and Numismatic Supplies",
            "5973": "Religious Goods Stores",
            "5975": "Hearing Aids–Sales, Service, Supply Stores",
            "5976": "Orthopedic Goods–Artificial Limb Stores",
            "5977": "Cosmetic Stores",
            "5978": "Typewriter Stores – Sales, Rentals, and Service",
            "5983": "Fuel Dealers – Fuel Oil, Wood, Coal, and Liquefied Petroleum",
        })
        """Load merchant category codes from predefined categories"""
        # Contracted Services (1500-2999)
        self.merchant_category_codes.update({
            "1520": "General Contractors–Residential and Commercial",
            "1711": "Air Conditioning, Heating and Plumbing Contractors",
            "1731": "Electrical Contractors",
            "1740": "Insulation, Masonry, Plastering, Stonework and Tile Setting Contractors",
            "1750": "Carpentry Contractors",
            "1761": "Roofing and Siding, Sheet Metal Work Contractors",
            "1771": "Concrete Work Contractors",
            "1799": "Contractors, Special Trade Contractors–not elsewhere classified",
            "2741": "Miscellaneous Publishing and Printing",
            "2791": "Typesetting, Plate Making and Related Services",
            "2842": "Specialty Cleaning, Polishing and Sanitation Preparations"
        })
        
        # Airlines (3000-3299)
        self.merchant_category_codes.update({
            "3000": "United Airlines",
            "3001": "American Airlines",
            "3002": "Pan American",
            "3003": "Eurofly Airlines",
            "3004": "Dragon Airlines",
            "3005": "British Airways",
            "3006": "Japan Airlines",
            "3007": "Air France",
            "3008": "Lufthansa",
            "3009": "Air Canada",
            "3010": "KLM (Royal Dutch Airlines)",
            "3011": "Aeroflot",
            "3012": "Qantas",
            "3013": "ITA Airways (Formerly Alitalia)",
            "3014": "Saudi Arabian Airlines",
            "3026": "Emirates Airlines",
            "3058": "Delta",
            "3066": "Southwest",
            "3070": "Flydubai",
            "3080": "Swoop Inc",
            "3082": "Korean Airlines",
            "3099": "Cathay Pacific",
            "3144": "Virgin Atlantic",
            "3168": "Hainan Airlines",
            "3169": "Riyadh Air",
            "3174": "Jetblue Airways",
            "3256": "Alaska Airlines",
            "3300": "Azul Air",
            "3301": "Wizz Air",
            "3302": "Flybe Ltd",
            "3303": "Tigerair",
            "3308": "China Southern Airlines"
        })
        
        # Car Rental (3300-3499)
        self.merchant_category_codes.update({
            "3351": "Affiliated Auto Rental",
            "3352": "American Intl Rent-A-Car",
            "3353": "Brooks Rent-A-Car",
            "3354": "Action Auto Rental",
            "3355": "Sixt Car Rental",
            "3357": "Hertz",
            "3359": "Payless Car Rental",
            "3366": "Budget Rent-A-Car",
            "3387": "Alamo Rent-A-Car",
            "3389": "Avis Rent-A-Car",
            "3390": "Dollar Rent-A-Car",
            "3393": "National Car Rental",
            "3395": "Thrifty Car Rental",
            "3405": "Enterprise Rent-A-Car",
            "3441": "Advantage Rent-A-Car"
        })
        
        # Lodging (3500-3999)
        self.merchant_category_codes.update({
            "3501": "Holiday Inns",
            "3502": "Best Western Hotels",
            "3503": "Sheraton",
            "3504": "Hilton Hotels",
            "3509": "Marriott",
            "3510": "Days Inns",
            "3512": "Inter-Continental Hotels",
            "3513": "Westin",
            "3615": "Travelodge",
            "3640": "Hyatt Hotels",
            "3649": "Radisson Hotels",
            "3700": "Motel 6",
            "3710": "The Ritz-Carlton",
            "3750": "Crowne Plaza Hotels",
            "3780": "Disney Resorts",
            "3807": "Element",
            "3812": "Hyatt Place",
            "3813": "Hotel Indigo",
            "3824": "Aria",
            "3825": "Vdara",
            "3828": "Cosmopolitan of Las Vegas",
            "3831": "Waldorf",
            "3834": "Baymont Inn & Suites",
            "3835": "Dolce Hotels and Resorts",
            "3836": "Hawthorn by Wyndham",
            "3837": "Hoshino Resorts",
            "3838": "Kimpton Hotels",
            "3839": "Kyoritsu Hotels",
            "3840": "Rio Hotels"
        })
        
        # Transportation Services (4000-4799)
        self.merchant_category_codes.update({
            "4011": "Railroads",
            "4111": "Local and Suburban Commuter Passenger Transportation, Including Ferries",
            "4112": "Passenger Railways",
            "4119": "Ambulance Services",
            "4121": "Taxicabs and Limousines",
            "4131": "Bus Lines",
            "4214": "Motor Freight Carriers and Trucking – Local and Long Distance, Moving and Storage Companies, and Local Delivery Services",
            "4215": "Courier Services – Air and Ground, and Freight Forwarders",
            "4225": "Public Warehousing and Storage – Farm Products, Refrigerated Goods, Household Goods, and Storage",
            "4411": "Steamship and Cruise Lines",
            "4457": "Boat Rentals and Leasing",
            "4468": "Marinas, Marine Service, and Supplies",
            "4511": "Airlines and Air Carriers (Not Elsewhere Classified)",
            "4582": "Airports, Flying Fields, and Airport Terminals",
            "4722": "Travel Agencies and Tour Operators",
            "4723": "Package Tour Operators – Germany Only",
            "4784": "Tolls and Bridge Fees",
            "4789": "Transportation Services (Not Elsewhere Classified)"
        })
        
        # Utility Services (4800-4999)
        self.merchant_category_codes.update({
            "4812": "Telecommunication Equipment and Telephone Sales",
            "4814": "Telecommunication Services, including Local and Long-Distance Calls, Credit Card Calls, Calls Through Use of Magnetic Stripe-Reading Telephones, and Fax Services",
            "4816": "Computer Network/Information Services",
            "4821": "Telegraph Services",
            "4829": "Money Transfer",
            "4899": "Cable, Satellite and Other Pay Television/Radio/Streaming Services",
            "4900": "Utilities – Electric, Gas, Water, and Sanitary"
        })
        
        # Retail (5000-5599)
        self.merchant_category_codes.update({
            "5045": "Computers, Computer Peripheral Equipment, Software",
            "5094": "Precious Stones and Metals, Watches and Jewelry",
            "5192": "Books, Periodicals and Newspapers",
            "5200": "Home Supply Warehouse Stores",
            "5211": "Building Materials, Lumber Stores",
            "5311": "Department Stores",
            "5411": "Grocery Stores, Supermarkets",
            "5499": "Miscellaneous Food Stores–Convenience Stores, Markets, Specialty Stores",
            "5541": "Service Stations (With or Without Ancillary Services)",
            "5542": "Fuel Dispenser, Automated"
        })
        
        # Restaurants and Food (5800-5899)
        self.merchant_category_codes.update({
            "5811": "Caterers",
            "5812": "Eating Places and Restaurants",
            "5813": "Bars, Cocktail Lounges, Discotheques, Nightclubs and Taverns",
            "5814": "Fast Food Restaurants"
        })
        
        # Miscellaneous Stores (5900-7299)
        self.merchant_category_codes.update({
            "5912": "Drug Stores and Pharmacies",
            "5921": "Package Stores–Beer, Wine and Liquor",
            "5941": "Sporting Goods Stores",
            "5942": "Book Stores",
            "5944": "Clock, Jewelry, Watch and Silverware Stores",
            "5945": "Game, Toy and Hobby Shops",
            "5947": "Card, Gift, Novelty and Souvenir Shops",
            "5992": "Florists",
            "5995": "Pet Shops, Pet Food and Supplies"
        })
        
        # Professional Services (8000-8999)
        self.merchant_category_codes.update({
            "8011": "Doctors–not elsewhere classified",
            "8021": "Dentists and Orthodontists",
            "8062": "Hospitals",
            "8099": "Health Practitioners, Medical Services–Not Elsewhere Classified",
            "8111": "Attorneys, Legal Services",
            "8220": "Colleges, Universities, Professional Schools and Junior Colleges",
            "8299": "Schools And Educational Services–Not Elsewhere Classified"
        })

class Card Creator:
    def __init__(self, card_type, card_number=None):
        self.card_type = card_type
        self.card_number = card_number or self.generate_number_by_type(card_type)

    def generate_number_by_type(self, card_type):
        prefix = ""
        if card_type.lower() == "visa":
            prefix = random.choice(["4"])
        elif card_type.lower() == "mastercard":
            prefix = random.choice(["51", "52", "53", "54", "55"])
        elif card_type.lower() == "amex" or card_type.lower() == "american express":
            prefix = random.choice(["34", "37"])
        elif card_type.lower() == "discover":
            prefix = random.choice(["6011", "65"])
        elif card_type.lower() == "jcb":
            prefix = "35"
        elif card_type.lower() == "diners club":
            prefix = random.choice(["36", "38"])
        elif card_type.lower() == "china unionpay":
            prefix = random.choice([str(i) for i in range(6200, 6250)])
        
        # Generate remaining digits (total length depends on card type)
        length = 16  # Default length for most cards
        if card_type.lower() == "amex" or card_type.lower() == "american express":
            length = 15
        elif card_type.lower() == "diners club":
            length = 14
            
        remaining_digits = length - len(prefix)
        random_digits = ''.join([str(random.randint(0, 9)) for _ in range(remaining_digits)])
        
        return f"{prefix}{random_digits}"

    def generate_card(self):
        return f"{self.card_type} Card Number: {self.card_number}"
    
    def MerchantCode(self):
        # Using the Merchant Category Codes from the document
        mcc_categories = {
            "Agricultural Services": ["0742", "0763", "0780"],
            "Contracted Services": ["1520", "1711", "1731", "1740", "1750", "1761", "1771", "1799", "2741", "2791", "2842"],
            "Transportation Services": ["4011", "4111", "4112", "4119", "4121", "4131", "4214", "4215", "4225", "4411", "4457", "4468", "4511", "4582", "4722", "4784", "4789"],
            "Utility Services": ["4812", "4814", "4816", "4821", "4829", "4899", "4900"],
            "Retail Outlet Services": ["5013", "5021", "5039", "5044", "5045", "5046", "5047", "5051", "5065", "5072", "5074", "5085", "5094", "5099", "5111", "5122", "5131", "5137", "5139", "5169", "5172", "5192", "5193", "5198", "5199", "5200", "5211", "5231", "5251", "5261", "5271", "5300", "5309", "5310", "5311", "5331", "5399", "5411", "5422", "5441", "5451", "5462", "5499", "5511", "5521", "5532", "5533", "5541", "5542", "5551", "5561", "5571", "5592", "5598", "5599"]
        }
        
        # Randomly select a category and then a code from that category
        category = random.choice(list(mcc_categories.keys()))
        code = random.choice(mcc_categories[category])
        
        return f"{code} - {category}"
    
    def display_card(self):
        print(self.generate_card())
        print(f"Merchant Category Code: {self.MerchantCode()}")
    
    def MerchantCode(self):
        """Return the assigned merchant code or a default if none assigned"""
        if self.assigned_merchant_category:
            return self.assigned_merchant_category
        return "1234-5678-9012-3456"  # Example merchant code
    
    def display_card(self):
        """Display card information"""
        print(self.generate_card())
    
    def get_merchant_category_description(self, mcc):
        """Get the description for a merchant category code"""
        if mcc in self.merchant_category_codes:
            return self.merchant_category_codes[mcc]
        return "Unknown Merchant Category"
    
    def assign_merchant_category(self, mcc):
        """Assign a merchant category code to this card"""
        if mcc in self.merchant_category_codes:
            self.assigned_merchant_category = mcc
            return True
        return False
    
    def list_available_merchant_categories(self, category=None):
        """
        List available merchant categories
        
        Args:
            category (str, optional): Filter by category prefix (e.g., "3" for travel)
        """
        print("Available Merchant Category Codes:")
        print("----------------------------------")
        
        for code, description in sorted(self.merchant_category_codes.items()):
            if category is None or code.startswith(category):
                print(f"{code}: {description}")
    
    def search_merchant_categories(self, search_term):
        """
        Search for merchant categories containing the search term
        
        Args:
            search_term (str): Term to search for in descriptions
        """
        search_term = search_term.lower()
        results = []
        
        for code, description in self.merchant_category_codes.items():
            if search_term in description.lower():
                results.append((code, description))
        
        if results:
            print(f"Found {len(results)} matching merchant categories:")
            for code, description in sorted(results):
                print(f"{code}: {description}")
        else:
            print("No matching merchant categories found.")
    
    def get_category_name(self, mcc):
        """
        Get the general category name for a merchant category code
        
        Args:
            mcc (str): Merchant Category Code
        
        Returns:
            str: Category name
        """
        mcc_num = int(mcc)
        
        if 1500 <= mcc_num <= 2999:
            return "Contracted Services"
        elif 3000 <= mcc_num <= 3299:
            return "Airlines"
        elif 3300 <= mcc_num <= 3499:
            return "Car Rental"
        elif 3500 <= mcc_num <= 3999:
            return "Lodging"
        elif 4000 <= mcc_num <= 4799:
            return "Transportation Services"
        elif 4800 <= mcc_num <= 4999:
            return "Utility Services"
        elif 5000 <= mcc_num <= 5599:
            return "Retail"
        elif 5600 <= mcc_num <= 5699:
            return "Clothing Stores"
        elif 5700 <= mcc_num <= 7299:
            return "Miscellaneous Stores"
        elif 7300 <= mcc_num <= 7999:
            return "Business Services"
        elif 8000 <= mcc_num <= 8999:
            return "Professional Services"
        elif 9000 <= mcc_num <= 9999:
            return "Government Services"
        else:
            return "Unknown Category"
    
    def validate_merchant_code(self, mcc):
        """
        Validate if a merchant code is in the correct format and exists
        
        Args:
            mcc (str): Merchant Category Code to validate
        
        Returns:
            tuple: (is_valid, message)
        """
        # Check if it's a string of digits
        if not mcc.isdigit():
            return False, "Merchant code must contain only digits"
        
        # Check if it's in the valid range
        mcc_num = int(mcc)
        if not (0 <= mcc_num <= 9999):
            return False, "Merchant code must be between 0000 and 9999"
        
        # Check if it exists in our database
        if mcc not in self.merchant_category_codes:
            return False, "Merchant code not found in database"
        
        return True, "Valid merchant code"