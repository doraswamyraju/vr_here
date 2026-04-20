import { 
    Building2, FileCheck, Users as UsersIcon, PieChart, ShieldCheck, Mail, Calculator, Briefcase, Globe
} from 'lucide-react';

export const SERVICE_CATALOG = {
    'pvt-ltd-registration': {
        title: 'Private Limited Registration',
        description: 'Launch your startup with the most credible legal structure. Get Certificate of Incorporation, MOA, AOA, PAN & TAN in 7 days.',
        icon: Building2,
        packages: [
            {
                id: 'consultation',
                name: 'Expert Consultation',
                price: 499,
                isAdjustable: true,
                description: 'Start here if you are unsure. Fee fully adjusted against registration.',
                features: ['30 Mins CA/CS Call', 'Business Structure Advice', 'Name Availability Check', 'Compliance Roadmap'],
                buttonText: 'Book Consultation'
            },
            {
                id: 'basic',
                name: 'Basic',
                price: 5499,
                description: 'Essential registration for verified startups.',
                features: ['Name Approval (RUN)', 'COI, PAN & TAN', 'MOA & AOA', '2 DIN & 2 DSC', 'PF/ESI/MSME registration'],
                buttonText: 'Select Basic'
            },
            {
                id: 'advance',
                name: 'Advance',
                price: 11399,
                isPopular: true,
                description: 'Complete compliance & web presence.',
                features: ['Everything in Basic', 'GST Registration', 'Import Export Code (IEC)', 'ISO Certification', 'Professional Website'],
                buttonText: 'Select Advance'
            }
        ]
    },
    'gst-registration': {
        title: 'GST Registration',
        description: 'Get your GST number quickly and start filing returns. Essential for businesses with turnover above thresholds.',
        icon: FileCheck,
        packages: [
            {
                id: 'consultation',
                name: 'Expert Consultation',
                price: 499,
                isAdjustable: true,
                description: 'Speak with our tax expert about your GST eligibility and documents.',
                features: ['30 Mins Call', 'Eligibility Check', 'Documents List Review', 'State-Specific Rules'],
                buttonText: 'Book Consultation'
            },
            {
                id: 'basic',
                name: 'Basic',
                price: 2569,
                description: 'Essential GST registration package.',
                features: ['New GST Registration', 'Updating Bank Account', '1st Month GST Return'],
                buttonText: 'Select Basic'
            },
            {
                id: 'expert',
                name: 'Expert',
                price: 9059,
                description: 'Complete tax compliance suite.',
                features: ['Everything in Basic', 'LUT Filing', 'IEC Code Application', '2 Months GST Returns', 'Priority Support'],
                buttonText: 'Select Expert'
            }
        ]
    },
    'partnership-firm': {
        title: 'Partnership Firm Registration',
        description: 'Ideal for small businesses with multiple owners. Shared responsibilities and faster decision making.',
        icon: UsersIcon,
        packages: [
            {
                id: 'consultation',
                name: 'Expert Consultation',
                price: 499,
                isAdjustable: true,
                description: 'Discuss partnership clauses and legal requirements with our experts.',
                features: ['Partnership Deed Advice', 'Clause Review', 'Tax Implication Call'],
                buttonText: 'Book Consultation'
            },
            {
                id: 'basic',
                name: 'Basic',
                price: 4899,
                description: 'Essential registration for partnership firms.',
                features: ['Deed Drafting', 'PAN & TAN Applications', 'Firm Registration', 'Notary Assistance'],
                buttonText: 'Select Basic'
            }
        ]
    },
    'income-tax-return': {
        title: 'Income Tax Return (ITR)',
        description: 'End-to-end ITR filing support for salaried, professionals, and businesses with compliance-first review.',
        icon: Calculator,
        packages: [
            {
                id: 'consultation',
                name: 'Expert Consultation',
                price: 499,
                isAdjustable: true,
                description: 'Review your tax computation and self-assessment with a CA.',
                features: ['Tax Planning Call', 'Computation Review', 'Deduction Guidance'],
                buttonText: 'Book Consultation'
            },
            {
                id: 'itr-filing',
                name: 'ITR Filing',
                price: 1499,
                description: 'Standard filing service for individuals/professionals.',
                features: ['ITR 1 to 4 Support', 'computation review', 'Notice response guidance'],
                buttonText: 'Get Started'
            }
        ]
    }
};
