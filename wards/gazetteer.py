"""Gazetteers: Indian given names and surnames, honorifics, relation markers,
administrative areas, and medical / English vocabulary that must never be read as a name.

Names are stored in Latin only. Devanagari mentions are compared through
translit.name_key(), so one list covers both scripts.
"""
from __future__ import annotations

from .translit import name_key

_GIVEN = """
aarav aarti aarushi abdul abhay abhishek abid adarsh aditi aditya afroz afsana agnes ahmad ahmed aisha ajay ajit
akash akbar akhilesh akram alka alok aman amar amarjeet amina amit amita amitabh amrita amrit anand anant anil
anita anjali anju ankit ankita anuj anupam anuradha anwar aparna archana arif arjun arshad arti arun aruna
arvind asha ashish ashok ashraf asif aslam atul avinash ayesha azad aziz babita babli babloo babu badal
balbir baldev balram balwant banwari basant beena bhagwati bharat bhavna bhola bhupendra bilal bimla bindu
brijesh chanchal chandan chandni chandra chandrakant chandrashekhar charan chetan chhaya daljeet daljit damini
deepa deepak deepika deepti devendra devesh dharam dharmendra dhiraj dhruv digvijay dilip dimple dinesh divya
durga dushyant ekta farah farhan farida faiz faizan farooq fatima feroz firoz gajendra ganesh gaurav gayatri
geeta gita girish gopal govind gulab gulshan gurmeet gurpreet gyan hafiz hamid hanif hansraj hari harish
hareesh harjeet harpreet harsh harshit hasan hemant hema hemlata himanshu hina hira husain hussain imran inder
indu iqbal irfan isha ishaan ishwar jagdish jagat jagjit jameel jamila janaki jaspreet jasbir jasvinder jaswant
jaya jayant jitendra jyoti kailash kajal kalpana kamal kamala kamla kamlesh kanchan kanta kapil karan karim
kartik kaushal kavita kavya keshav khalid kiran kishan kishore krishna kuldeep kulwant kumkum kunal kusum
lakhan lakshmi lalit lalita lata laxmi leela lokesh madan madhu madhuri mahavir mahendra mahesh mahima
mamta manish manju manoj mansoor manju mary mayank mayawati meena meera megha mehboob mohan mohini mohit
mohsin monika mukesh munni murli nadeem nafees naina nand nandini narayan narendra naresh nargis naseem
nasir naveen navneet nazia neelam neeraj neetu neha nikhil nikita nirmala nisha nitin nitu noor nusrat
om omprakash pankaj parvati parveen pawan payal pooja poonam prabhat pradeep prakash pramod pranav prashant
pratap pratibha praveen preeti prem priya priyanka puja pushpa rachna radha radhika raghav raghu rahim rahul
raj rajan rajat rajendra rajesh rajeev rajiv rajkumar rajni rakesh rakhi ram ramesh rameshwar rani ranjana
ranjeet ranjit rashid rashmi ravi ravindra rehana reena rekha renu reshma rina rinku ritu rohit roop roshan
roshni rubina ruby rukhsana sachin sadhana sahil saira sajid salim salma sameer samir sandeep sangeeta sanjay
sanjeev santosh sapna sarita saroj satish satyam savita seema shabana shabnam shahid shahnaz shakeel shakti
shakuntala shalini shankar shanti sharad sharda shashi sheela sheetal shilpa shiv shivam shobha shraddha
shreya shubham shyam siddharth sneha sohan sonam sonia sonu subhash sudha sudhir suman sumit sunil sunita
suraj surendra suresh surinder sushil sushila swati tabassum tahir tanvi tara tariq tarun tejpal tulsi uday
uma umesh urmila usha uttam vandana varsha veena vijay vikas vikram vimal vinay vineet vinod vipin virendra
vishal vishnu vivek yash yashoda yogesh yusuf zainab zakir zara zubair zubeida zeenat sukhwinder harjinder
paramjeet manpreet navjot simran gurdeep jagjeet anthony joseph thomas john peter paul james george mathew
francis maria elizabeth grace rose stella esther ruth sushma kalawati shivani anamika shabnam firdaus nazma
shamim sabina sultana shaheen yasmin rubeena gulnaz mumtaz naushad irshad intezar ishtiyaq javed jawed
mushtaq nawab qasim rizwan sarfaraz shoaib wasim waseem zaheer zahid zafar zeeshan sahid ramkali ramvati
phoolmati chameli dulari kamini kesar lajwanti maya prabha rampyari sampat santra sudama surajpal ramdhan
ramnath ramlal shivlal motilal chhotelal banarsi bhagwan buddhu kallu mangal munna pappu raju sukhdev
sukhram jagannath hariom omkar shivkumar ramkishan ramashankar dayaram ghanshyam radheshyam rambabu
ramkumar rampal ramsingh ramavtar shivshankar jaiprakash kamta ramprasad sitaram
nasreen nasrin shamshad gulzar shabbir sabir sajda sakina tasleem yasmeen razia rukhsar shaista noorjahan
"""

_SURNAMES = """
agarwal agrawal ahmad ahmed ali ansari arora awasthi bajpai bajwa bano begum bhardwaj bhatt bhatia bisht
chandra chaturvedi chaubey chaudhary chaudhari chauhan chaurasia dixit dubey dwivedi gautam gill goel gupta
hussain jaiswal jain joshi kaur khan khanna khatoon kashyap kohli kumar kumari kushwaha lal lodhi lodh
maurya mehta mishra mittal malik masih maurya nishad pandey pande pandit patel pathak paswan prajapati
qureshi rajput rana rao rathore rawat rizvi saxena shah sharma shukla siddiqui singh sinha soni srivastava
thakur tiwari tripathi upadhyay usmani varma verma yadav zaidi kesarwani rastogi bhargava saini sahu
kannaujia kanojia rawal tyagi chaudhry chakraborty banerjee mukherjee das sen ghosh bose iyer nair menon
pillai reddy naidu shetty kulshrestha awasthi bajpayee nigam mathur asthana khare shrivastava pal baghel
bind kewat mallah dhobi kori pasi rajbhar valmiki jatav ahirwar sonkar diwakar bharti gond kol tharu
qadri naqvi abbasi farooqui hashmi jafri kazmi rahman haider raza mirza beg pathan sheikh shaikh
singh sidhu sandhu dhillon grewal bedi bains thomas joseph fernandes dsouza
"""

GENERIC_NAME_TOKENS = {
    "devi", "kumar", "kumari", "md", "mohd", "ji", "bano", "begum", "lal", "singh", "kaur", "prasad",
    "chand", "nath", "ram", "khatoon", "bibi", "bai",
}

GIVEN_NAMES = set(_GIVEN.split())
SURNAMES = set(_SURNAMES.split())
ALL_NAMES = GIVEN_NAMES | SURNAMES
GIVEN_KEYS = {name_key(n) for n in GIVEN_NAMES if len(n) >= 3}
SURNAME_KEYS = {name_key(n) for n in SURNAMES if len(n) >= 3}

# Honorifics written after a name: "Shahid sahab", "Asha ji", "Kamal Bhaiya", "Fatima amma".
HONORIFIC_SUFFIX = {
    "ji", "jee", "sahab", "saheb", "sahib", "bhai", "bhaiya", "bhaiyya", "didi", "behenji", "behen",
    "bahen", "bahenji", "amma", "ammi", "chacha", "chachi", "bua", "mausi", "dada", "dadi", "nana", "nani",
    "babu", "baba", "uncle", "aunty", "aunti", "madam", "maaji", "mataji", "pitaji", "bhabhi", "beta",
    "beti", "kaka", "kaki", "tau", "tai", "bhaisahab",
    "जी", "साहब", "साहेब", "दीदी", "भैया", "भाई", "अम्मा", "बाबू", "चाचा", "चाची", "दादी", "दादा", "बहनजी",
    "माताजी", "बाबा",
}
HONORIFIC_PREFIX = {
    "shri", "sri", "shree", "smt", "srimati", "shrimati", "kumari", "km", "mr", "mrs", "ms", "miss", "master",
    "sushri", "janab", "begum", "late", "स्व", "श्री", "श्रीमती", "कुमारी", "सुश्री",
}
DOCTOR_PREFIX = {"dr", "doctor", "डॉ", "डा", "डॉक्टर", "prof", "consultant"}

RELATION_MARKERS = [
    # (regex, relation word); C/O and H/O are ambiguous and handled by detect.py
    r"S\s*/\s*[Oo]", r"D\s*/\s*[Oo]", r"W\s*/\s*[Oo]", r"Son\s+of", r"Daughter\s+of", r"Wife\s+of",
    r"Husband\s+of", r"Father\s*:", r"Husband\s*:", r"Guardian\s*:", r"पुत्र", r"पुत्री", r"पत्नी", r"पति",
    r"सुपुत्र", r"सुपुत्री", r"बेटा", r"बेटी",
]

# Uttar Pradesh districts (public administrative areas), Latin and Devanagari.
DISTRICTS = {
    "agra": "आगरा", "aligarh": "अलीगढ़", "ambedkar nagar": "अम्बेडकर नगर", "amethi": "अमेठी",
    "amroha": "अमरोहा", "auraiya": "औरैया", "ayodhya": "अयोध्या", "azamgarh": "आजमगढ़", "baghpat": "बागपत",
    "bahraich": "बहराइच", "ballia": "बलिया", "balrampur": "बलरामपुर", "banda": "बांदा", "barabanki": "बाराबंकी",
    "bareilly": "बरेली", "basti": "बस्ती", "bijnor": "बिजनौर", "budaun": "बदायूं", "bulandshahr": "बुलंदशहर",
    "chandauli": "चंदौली", "chitrakoot": "चित्रकूट", "deoria": "देवरिया", "etah": "एटा", "etawah": "इटावा",
    "farrukhabad": "फर्रुखाबाद", "fatehpur": "फतेहपुर", "firozabad": "फिरोजाबाद", "gautam buddh nagar": "गौतम बुद्ध नगर",
    "ghaziabad": "गाजियाबाद", "ghazipur": "गाजीपुर", "gonda": "गोंडा", "gorakhpur": "गोरखपुर", "hamirpur": "हमीरपुर",
    "hapur": "हापुड़", "hardoi": "हरदोई", "hathras": "हाथरस", "jalaun": "जालौन", "jaunpur": "जौनपुर",
    "jhansi": "झांसी", "kannauj": "कन्नौज", "kanpur dehat": "कानपुर देहात", "kanpur nagar": "कानपुर नगर",
    "kanpur": "कानपुर", "kasganj": "कासगंज", "kaushambi": "कौशाम्बी", "kushinagar": "कुशीनगर",
    "lakhimpur kheri": "लखीमपुर खीरी", "kheri": "खीरी", "lalitpur": "ललितपुर", "lucknow": "लखनऊ",
    "maharajganj": "महराजगंज", "mahoba": "महोबा", "mainpuri": "मैनपुरी", "mathura": "मथुरा", "mau": "मऊ",
    "meerut": "मेरठ", "mirzapur": "मिर्जापुर", "moradabad": "मुरादाबाद", "muzaffarnagar": "मुजफ्फरनगर",
    "pilibhit": "पीलीभीत", "pratapgarh": "प्रतापगढ़", "prayagraj": "प्रयागराज", "rae bareli": "रायबरेली",
    "raebareli": "रायबरेली", "rampur": "रामपुर", "saharanpur": "सहारनपुर", "sambhal": "संभल",
    "sant kabir nagar": "संत कबीर नगर", "shahjahanpur": "शाहजहांपुर", "shamli": "शामली", "shravasti": "श्रावस्ती",
    "siddharthnagar": "सिद्धार्थनगर", "sitapur": "सीतापुर", "sonbhadra": "सोनभद्र", "sultanpur": "सुल्तानपुर",
    "unnao": "उन्नाव", "varanasi": "वाराणसी", "bhadohi": "भदोही",
}
DISTRICT_DEVA = {v: k for k, v in DISTRICTS.items()}
STATES = {"uttar pradesh", "up", "u.p.", "उत्तर प्रदेश", "india", "in", "bharat"}

VILLAGE_SUFFIXES = (
    "pur", "puri", "purwa", "ganj", "nagar", "garh", "abad", "mau", "dih", "khera", "kheda", "khurd", "kalan",
    "gaon", "gram", "pura", "wala", "bagh", "tola", "basti", "patti", "sarai", "ghat", "kot", "ner",
)
VILLAGE_WORDS = {"khurd", "kalan", "buzurg", "purwa", "khas"}

# Words that look like capitalised names in clinical text but are not people.
NON_NAME_WORDS = set("""
a an the and or of in on at to for with without by from as is was are be been has have had not no yes
patient patients pt pts name names age sex gender male female m f yrs yr years year y months month days day
weeks week hours hour date time ward bed room unit icu opd ipd er emergency casualty hospital clinic centre
center lab laboratory diagnostics pathology dept department medicine surgery medical surgical pulmonology
neurology nephrology cardiology orthopaedics orthopedics gynaecology obstetrics paediatrics pediatrics ent
ophthalmology dermatology psychiatry oncology urology gastroenterology general district community primary
health government govt private charitable multispeciality multispecialty super speciality seva sadan
jyoti jeevan sanjeevani arogya lifeline city pathkind diagnostic routine panel report reports result results
discharge summary admission admitted discharged consultant doctor dr nurse sister staff attendant relative
relatives visitor visitors guardian informant caller mob mobile phone ph tel contact address addr add vill
village gram tehsil distt district dist pin pincode state uttar pradesh india bharat house h no makan
mohalla near opp opposite behind beside temple mandir masjid gurudwara church school bhawan panchayat tanki
pani road marg chowk bazar bazaar market colony nagar basti mata kali shiv hanuman jama primary
diagnosis diagnoses complaint complaints presenting history course treatment treated advice adv review rx
tab tabs cap caps inj syp syrup oint drops tablet capsule injection iv im sc po od bd tds qid hs sos stat
mg mcg g gm ml l iu units unit dose dosage x continue stop start started stable condition improved
fever cough cold pain abdomen headache giddiness vomiting loose stools weakness breathlessness exertion
burning micturition expectoration body ache chest fatigue swelling diabetes hypertension htn dm dm2
tb att asthma copd anaemia anemia dengue malaria typhoid jaundice hepatitis pneumonia sepsis infection
urinary tract site specified unspecified essential type disease syndrome palsy failure acute chronic
kidney renal liver heart cardiac stroke fracture injury surgery operation procedure done repair
cholecystectomy appendicectomy laparoscopic cataract phacoemulsification section caesarean hernia
inguinal session haemodialysis dialysis whipple pancreaticoduodenectomy stimulation brain deep
haemoglobin hemoglobin sugar blood random serum creatinine sodium potassium platelet count wbc total
hba1c tsh urea bilirubin sgpt sgot cholesterol glucose fasting pp bp pulse temp spo2 rr weight height
paracetamol dolo amlodipine telmisartan ramipril levothyroxine pantoprazole metformin glimepiride
doxycycline ceftriaxone azithromycin amoxicillin ferrous sulphate folic acid rifampicin isoniazid insulin
atorvastatin aspirin clopidogrel ondansetron omeprazole ranitidine cetirizine salbutamol prednisolone
low salt diet diabetic sulfa drugs allergic allergy old card merged verify identity next visit visits
sent arrival referred worker anganwadi anm mitanin addison addisons crohn crohns bell bells
parkinson parkinsons alzheimer alzheimers hodgkin hodgkins down graves cushing wilson huntington
guillain barre kawasaki raynaud sjogren tourette asperger burkitt kaposi meniere hashimoto
forwarded attachment pdf jpg image photo scan scanned consent form witness witnessed signed signature
helpdesk ticket billing query closed open pending settled approved status claim bill amount package
policy insurance payer pmjay ayushman card export exported system module records clerk generated source
path file files data research request extract extracts prepared cell it codes follow icd loinc snomed
note notes nursing round evening morning night raat subah shaam theek hai ho gaya gayi diya liya
ka ki ke ko se me mein par aur bhi nahi abhi kam kha rahe hain sakte chal phir utar band ulti bukhar
neend aayi dawai pe le sugar control koi problem call karo bola lena dr ne
trip from oxygen given en route called sample received tests test value unit range reference ref
mr mrs ms shri smt sri km kumari late
monday tuesday wednesday thursday friday saturday sunday january february march april may june july
august september october november december jan feb mar apr jun jul aug sep sept oct nov dec
""".split())

# Words that end a name span when they follow name-like tokens.
NAME_STOP_WORDS = NON_NAME_WORDS | HONORIFIC_SUFFIX

ORG_WORDS = {
    "hospital", "clinic", "centre", "center", "lab", "labs", "laboratory", "diagnostics", "diagnostic",
    "pathology", "pharmacy", "medical", "trust", "foundation", "college", "institute", "sadan", "seva",
    "charitable", "multispeciality", "multispecialty", "nursing", "home", "health", "care", "phc", "chc",
    "pvt", "ltd", "limited", "services", "department", "dept", "ward", "unit", "insurance", "company",
}


def is_known_name_token(tok: str) -> bool:
    t = tok.lower().strip(".")
    if t in ALL_NAMES:
        return True
    k = name_key(tok)
    return len(t) >= 5 and len(k) >= 4 and (k in GIVEN_KEYS or k in SURNAME_KEYS) and t not in NON_NAME_WORDS


def is_given_name(tok: str) -> bool:
    t = tok.lower().strip(".")
    if t in GIVEN_NAMES:
        return True
    k = name_key(tok)
    return len(t) >= 5 and len(k) >= 4 and k in GIVEN_KEYS and t not in NON_NAME_WORDS
